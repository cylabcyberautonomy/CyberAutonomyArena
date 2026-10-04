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
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "strategy"})
    code_dir_field = "deception_dir"          # Defense/Perry repo for this defender (per-plugin)
    executes_from_box = True                   # box-only execution: deploy the box agent + arm the env channel
    code_python_field = "deception_python"
    strategy: str  # e.g. "DoNothing", "StaticLayered", "ReactiveLayered"
    arsenal: dict[str, int] = {}
    max_decoys: int = 5  # upper bound on decoys this run may deploy; pre-reserved at admission so a
    #                      mid-run/arming add_host draws from already-held capacity (never blocks).

    def defender_vm_budget(self) -> list[tuple[int, int, int]]:
        """Pre-reserve one m1.small (1 vCPU / 2048 MB / 20 GB) per potential decoy. The env's add_host
        draws from this budget; add_host beyond it is rejected. A DeployDecoy strategy needs this (>0);
        a non-decoy strategy can set max_decoys=0."""
        return [(1, 2048, 20)] * max(0, self.max_decoys)

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
        env_spec,
        prepared: PreparedDefender,
    ) -> dict:
        # No topology_spec: this defender builds its Perry Network from the arena-injected
        # defender_env_spec (the env resolves backend names), not a backend topology.
        built = {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "arsenal": self.arsenal,
        }
        built.update(self._env_spec_key(env_spec))   # agent-facing host inventory (typed arg)
        built.update(self._baton_keys(prepared))  # box ES tunnel url + indices + box agent (Phase A)
        return built

    async def provision_box(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
        needs_agent: bool = False,
    ) -> PreparedDefender:
        # PHASE A (runs BEFORE build_config): stand up this run's OWN per-experiment ES on the defender box
        # + the ssh -L tunnel, and — when this run armed dynamic topology (needs_agent) — deploy + start the
        # box agent so the decoy deploy (Phase B) can route host actions to it. Both take the env-produced
        # box inventory + access (NOT a written config) and RETURN their values; build_config() bakes them
        # into the runner config via the baton. Blocking SSH work, so off the event loop.
        box_cfg = {
            "defender_env_spec": defender_env_spec.model_dump() if defender_env_spec is not None else {},
            "defender_setup_access": [a.model_dump() for a in (defender_access or [])],
        }
        loop = asyncio.get_event_loop()
        es = await loop.run_in_executor(None, self.prepare_box_es, box_cfg, experiment_name, cfg)
        baton = dict(es)
        if needs_agent:
            box_cfg.update(es)  # the box-agent config reads sysflow_index from prepare_box_es's output
            agent = await loop.run_in_executor(None, self.prepare_box_agent, box_cfg, experiment_name, cfg)
            baton.update(agent)
        return PreparedDefender(armed_in_setup=False, **baton)

    async def prepare(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> PreparedDefender:
        # PHASE B (after build_config + config write): EXTERNAL arming — run the strategy's prepare phase in
        # the deception venv to completion. For a static/naive strategy (Perry Strategy.ARMS_IN_SETUP) this
        # DEPLOYS the decoys + plants honey-creds/fake data now; for a reactive strategy it is a no-op (it
        # arms inside its loop). It reads the written config (es_url / box_agent_* already baked in by
        # build_config from the Phase-A baton). Blocks and RAISES on deploy failure, so an undefended
        # environment is never handed to the attacker. (Box ES + box agent standup moved to provision_box.)
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
            Path(__file__).parent / "runner.py", config_path, cfg, log_path,
            self._code_dir(cfg), self._code_python(cfg),
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

    # -- box agent deploy (the defender's in-environment effector) ---------------------------------
    # Copied per dynamic-defender plugin (box_agent_install.sh co-located), like prepare_box_es. Ships the
    # Perry runtime to the bare box, starts the agent on box:8900, opens a harness->box ssh -L tunnel (the
    # box is in-env, only reachable via the bastion), and injects box_agent_host/port/token into the config
    # the runner reads so RemoteEnvOrchestrator.from_config can reach it. NOT YET LIVE-VALIDATED.
    def _box_agent_tunnel_pidfile(self, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "box_agent_tunnel.pid"

    def prepare_box_agent(self, src_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        import json as _json
        import secrets
        import shlex
        import socket
        import time

        cfgd = src_cfg
        box = (cfgd.get("defender_env_spec") or {}).get("box") or {}
        box_ip = box.get("ip")
        if not box_ip:
            raise RuntimeError("no defender box in defender_env_spec; box agent requires one")
        access = next((a for a in cfgd.get("defender_setup_access", []) if a.get("host") == box_ip), None)
        if not access or not access.get("ssh_key"):
            raise RuntimeError(f"defender box {box_ip} present but no SetupAccess with an ssh_key")
        key = os.path.expanduser(access["ssh_key"])
        common = shlex.split(access.get("ssh_common_args") or "")
        user = access.get("user", "root")
        port = str(access.get("port", 22))
        ssh_opts = ["-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", "-p", port, *common]
        ssh_base = ["ssh", *ssh_opts]
        target = f"{user}@{box_ip}"
        repo_dir = str(self._code_dir(cfg))

        # 1. ship ONLY the ansible/ YAML tree + the standalone agent (the self-contained agent imports no
        #    Perry Python — which needs py3.10+ — so the box's py3.8 is fine). Via the bastion jump.
        rsync_e = "ssh " + " ".join(shlex.quote(o) for o in ssh_opts)
        subprocess.run(
            ["rsync", "-a", "--delete", "-e", rsync_e, "--exclude", ".git", "--exclude", "__pycache__",
             repo_dir.rstrip("/") + "/ansible/", f"{target}:/root/ansible/"],
            check=True, timeout=600)
        agent_src = Path(repo_dir) / "defender" / "box_agent" / "agent.py"
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_agent.py"],
                       input=agent_src.read_text(), text=True, check=True, timeout=60)
        # 2. ship the scoped key the box agent's AnsibleRunner uses to reach victims (box -> victim direct).
        subprocess.run([*ssh_base, target, "cat > /root/scoped_key && chmod 600 /root/scoped_key"],
                       input=Path(key).read_text(), text=True, check=True, timeout=60)
        # 3. write + ship the box-agent config.
        token = secrets.token_urlsafe(24)
        box_cfg = {
            "token": token, "host": "127.0.0.1", "port": 8900,
            "ssh_key_path": "/root/scoped_key", "ansible_dir": "/root/ansible", "log_dir": "/root",
            # A decoy's SysFlow exports to the box's OWN ES, reached from the decoy at the box's in-env
            # address (the box runs ES on :9200 from prepare_box_es). Plain HTTP, no auth (box ES has
            # security disabled). NOTE live-unknown: decoy->box:9200 routing + box ES binding 0.0.0.0.
            "es_address": f"http://{box_ip}:9200",
            "es_index": cfgd.get("sysflow_index", "sysflow"),
        }
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_config.json"],
                       input=_json.dumps(box_cfg), text=True, check=True, timeout=60)
        # 4. ship + run the install/start script (idempotent).
        script = (Path(__file__).parent / "box_agent_install.sh").read_text()
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_install.sh && chmod +x /root/box_agent_install.sh"],
                       input=script, text=True, check=True, timeout=60)
        subprocess.run([*ssh_base, target, "/root/box_agent_install.sh"], check=True, timeout=600)
        # 5. open a harness->box:8900 ssh -L tunnel (box is in-env, reachable only through the bastion).
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            lport = s.getsockname()[1]
        tunnel = subprocess.Popen([*ssh_base, "-N", "-L", f"{lport}:localhost:8900", target],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pidfile = self._box_agent_tunnel_pidfile(experiment_name, cfg)
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(tunnel.pid))
        # 6. wait for the agent's /health through the tunnel.
        import urllib.request
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{lport}/health", timeout=5) as r:
                    if r.status == 200:
                        break
            except Exception:  # noqa: BLE001
                time.sleep(3)
        else:
            raise RuntimeError(f"box agent did not answer /health on {box_ip}:8900 within 120s")
        # 7. inject the reachable host/port/token into the config the runner reads.
        return {"box_agent_host": "127.0.0.1", "box_agent_port": lport, "box_agent_token": token}

    def prepare_box_es(self, box_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        """Install ES on the defender box (idempotent) and open a harness-host->box:9200 ssh -L tunnel.
        Writes es_url + falco_index/sysflow_index into the config JSON the runner reads, drops an
        es_tunnel.pid for teardown, and returns the injected dict. Fail-closed: raises if the topology
        has no defender box — box ES is required, there is no shared-harness-ES fallback."""
        import json as _json
        import shlex
        import socket
        import time

        cfgd = box_cfg
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

        return {"es_url": es_url, "falco_index": "falco", "sysflow_index": "sysflow"}

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
