from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Literal, Optional

from pydantic import field_validator

from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....environment import DeployedEnvironment
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin, PreparedDefender


class DeceptionDefenderPlugin(DefenderPlugin, config_type="deception"):
    type: Literal["deception"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "strategy", "topology_spec"})
    strategy: str  # e.g. "DoNothing", "StaticLayered", "ReactiveLayered"
    arsenal: dict[str, int] = {}

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value):
        if isinstance(value, list):
            return value[0] if value else "DoNothing"
        return value

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "deception",
            "label": "Deception",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Strategy",
                    "key": "strategy",
                    "options": [
                        "DoNothing", "StaticLayered", "ReactiveLayered",
                        "ReactiveStandalone", "StaticStandalone",
                        "NaiveDecoyCredential", "NaiveDecoyHost",
                    ],
                    "short_names": {
                        "DoNothing": "donothing",
                        "StaticLayered": "static_lyr",
                        "ReactiveLayered": "react_lyr",
                        "ReactiveStandalone": "react_solo",
                        "StaticStandalone": "static_solo",
                        "NaiveDecoyCredential": "decoy_cred",
                        "NaiveDecoyHost": "decoy_host",
                    },
                },
                {
                    "field_type": "key_value_pairs",
                    "label": "Arsenal",
                    "key": "arsenal",
                    # Keys must match what each Strategy.initialize() actually reads from
                    # arsenal.storage (see defender/strategy/*.py in the deception repo) -
                    # they're capability/Action class names, not free-form labels. Every
                    # strategy but DoNothing needs at least one of these three:
                    # DeployDecoy + HoneyCredentials (Static*/Reactive*/NaiveDecoyCredential/
                    # NaiveDecoyHost), plus RestoreServer for ReactiveLayered/
                    # ReactiveStandalone specifically. A wrong/missing key here is a
                    # KeyError crash in Strategy.initialize(), not a silent no-op -
                    # confirmed live (StaticLayered crashed on a stale "honeypot" default
                    # that doesn't match anything any Strategy class actually looks up).
                    "entries": [
                        {"key": "DeployDecoy", "value": "2"},
                        {"key": "HoneyCredentials", "value": "2"},
                        {"key": "RestoreServer", "value": "2"},
                    ],
                    "key_short_names": {
                        "DeployDecoy": "decoy",
                        "HoneyCredentials": "honeycred",
                        "RestoreServer": "restore",
                    },
                },
            ],
        }

    def box_ingress(self) -> dict[str, list[int]]:
        # Reactive strategies read the box ES telemetry; static ones ignore it (harmless to route).
        return {"telemetry": [9200]}

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict:
        return {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "arsenal": self.arsenal,
            "topology_spec": environment.topology_spec if environment else None,
        }

    async def prepare(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> PreparedDefender:
        # 1) Stand up this run's OWN per-experiment ES on the defender box + the ssh -L tunnel
        #    (prepare_box_es, copied per plugin); injects es_url into the config the subprocesses read.
        #    Blocking SSH work, so off the event loop.
        await asyncio.get_event_loop().run_in_executor(
            None, self.prepare_box_es, config_path, experiment_name, cfg)
        # 2) EXTERNAL arming: run the strategy's prepare phase in the deception venv to completion. For a
        #    static/naive strategy (Perry Strategy.ARMS_IN_SETUP) this DEPLOYS the decoys + plants
        #    honey-creds/fake data now; for a reactive strategy it is a no-op (it arms inside its loop).
        #    Blocks and RAISES if the deploy fails, so an undefended environment is never handed to the
        #    attacker — the slow decoy deploy no longer races the attacker inside the run loop.
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        return await self._run_prepare_and_wait(
            Path(__file__).parent / "runner.py", config_path, experiment_name, cfg, log_path
        )

    async def teardown(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
    ) -> None:
        # Kill the harness-host->box ES ssh -L tunnel. (Stray decoy VMs this plugin's strategies deploy
        # via DeployDecoy are reaped by the environment's own teardown, not here.)
        self._teardown_box_es_tunnel(experiment_name, cfg)

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        # The box ES + the strategy's external arming happened in prepare(); here we only launch the
        # long-running reactive loop ("run" mode -> runner.py calls defender.start(prepared=True)).
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        return await self._run_deception_script(
            Path(__file__).parent / "runner.py", config_path, cfg, log_path
        )

    # -- per-experiment Elasticsearch on the defender box -----------------------------------------
    # The environment provisions a bare, isolated box (defender_subnet) and ships sensor telemetry to it
    # via its relay (victim -> relay(mgmt:9200) -> box:9200) under plain "falco"/"sysflow" indices. This
    # defender stands up ES on the box (bare box, no docker/java -> the ES tarball bundles a JDK) and opens
    # an ssh -L tunnel so its detection loop reads the box's OWN ES at localhost:<port> — each run gets its
    # own ES (no shared harness ES), fixing cross-experiment contamination + shard-cap arming failures.
    # Copied into each telemetry-consuming plugin (box_es_install.sh is co-located) so each plugin is
    # self-contained — no shared base method or helper module.
    @staticmethod
    def _es_tunnel_pidfile(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "es_tunnel.pid"

    def prepare_box_es(self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        """Install ES on the defender box (idempotent) and open a harness-host->box:9200 ssh -L tunnel.
        Writes es_url + falco_index/sysflow_index into the config JSON the runner reads, drops an
        es_tunnel.pid for teardown, and returns the injected dict. Fail-closed: raises if the topology
        has no defender box — box ES is required, there is no shared-harness-ES fallback."""
        import json as _json
        import shlex
        import socket
        import time

        cfgd = _json.loads(Path(config_path).read_text())
        box = (cfgd.get("defender_env_spec") or {}).get("box") or {}
        box_ip = box.get("ip")
        if not box_ip:
            raise RuntimeError(
                "no defender box in defender_env_spec; box ES is required (no shared-harness-ES fallback)")

        access = next((a for a in cfgd.get("defender_setup_access", []) if a.get("host") == box_ip), None)
        if not access or not access.get("ssh_key"):
            raise RuntimeError(f"defender box {box_ip} present but no SetupAccess entry with an ssh_key")
        key = os.path.expanduser(access["ssh_key"])
        common = shlex.split(access.get("ssh_common_args") or "")
        user = access.get("user", "root")
        port = str(access.get("port", 22))
        ssh_base = ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", "-p", port, *common]
        target = f"{user}@{box_ip}"

        # 1. ship + run the ES install (idempotent: the script no-ops if :9200 is already up).
        #    Two steps so the stdin write completes before the channel closes (backgrounding a
        #    stdin-reading remote cmd in one shot truncates it).
        script = (Path(__file__).parent / "box_es_install.sh").read_text()
        subprocess.run([*ssh_base, target, "cat > /root/box_es_install.sh && chmod +x /root/box_es_install.sh"],
                       input=script, text=True, check=True, timeout=60)
        subprocess.run([*ssh_base, target,
                        "nohup /root/box_es_install.sh > /root/es_install.log 2>&1 & echo launched"],
                       check=True, timeout=30)
        # 2. wait for ES on the box (fresh install downloads a ~650MB tarball -> allow a few min).
        deadline = time.time() + 300
        while time.time() < deadline:
            r = subprocess.run([*ssh_base, target, "curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:9200"],
                               capture_output=True, text=True, timeout=30)
            if r.stdout.strip() == "200":
                break
            time.sleep(10)
        else:
            raise RuntimeError(f"defender-box ES did not come up on {box_ip}:9200 within 300s")

        # 3. open an ssh -L tunnel harness-host:<lport> -> box:9200 (via the box access's bastion jump).
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            lport = s.getsockname()[1]
        tunnel = subprocess.Popen(
            [*ssh_base, "-N", "-L", f"{lport}:localhost:9200", target],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pidfile = self._es_tunnel_pidfile(experiment_name, cfg)
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(tunnel.pid))

        es_url = f"http://127.0.0.1:{lport}"
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                import urllib.request
                with urllib.request.urlopen(es_url, timeout=5) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(2)
        else:
            raise RuntimeError(f"ssh -L tunnel to box ES never became reachable at {es_url}")

        injected = {"es_url": es_url, "falco_index": "falco", "sysflow_index": "sysflow"}
        cfgd.update(injected)
        Path(config_path).write_text(_json.dumps(cfgd, indent=2))
        return injected

    @classmethod
    def _teardown_box_es_tunnel(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """Kill the harness-host->box ES ssh -L tunnel (ES itself dies with the box at env teardown)."""
        pidfile = cls._es_tunnel_pidfile(experiment_name, cfg)
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, 15)
        except (OSError, ValueError):
            pass
        finally:
            pidfile.unlink(missing_ok=True)
