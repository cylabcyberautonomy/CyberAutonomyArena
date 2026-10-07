from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Literal, Optional

from pydantic import field_validator

from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin, PreparedDefender


# The harness-run reactive-loop process, launched in setup() and handed to run_start via start(). Keyed by experiment_name.
_PROCS: dict = {}


class PreparedDeception(PreparedDefender):
    """deception's box-telemetry baton: the box ES tunnel, falco/sysflow indices, and the box-agent endpoint. Baked into the runner config by build_config."""
    es_url: Optional[str] = None
    falco_index: Optional[str] = None
    sysflow_index: Optional[str] = None
    box_agent_host: Optional[str] = None
    box_agent_port: Optional[int] = None
    box_agent_token: Optional[str] = None
    # The env-action channel: one token'd TCP endpoint the arena armed on harness-loopback. build_config bakes these.
    env_action_url: Optional[str] = None
    env_action_token: Optional[str] = None


class DeceptionDefenderPlugin(DefenderPlugin, config_type="deception"):
    type: Literal["deception"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "strategy"})
    code_dir_field = "deception_dir"          # Defense/Perry repo for this defender
    uses_env_actions = True                    # issues env-actions (decoy deploy / restore)
    code_python_field = "deception_python"
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
                    # Keys must match what each Strategy.initialize() reads from arsenal.storage
                    # (capability/Action class names). A wrong or missing key is a KeyError crash, not a no-op.
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
        # Reactive strategies read the box ES telemetry. Static ones ignore it (harmless to route).
        return {"telemetry": [9200]}

    def build_config(
        self,
        experiment_name: str,
        env_spec,
        prepared: PreparedDefender,
    ) -> dict:
        # No topology_spec: this defender builds its Perry Network from the arena-injected defender_env_spec.
        built = {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "arsenal": self.arsenal,
        }
        # bake this plugin's own box baton (es tunnel, indices, box-agent endpoint), opaque to the base.
        built.update({k: v for k, v in prepared.model_dump().items() if v is not None})
        return built

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> PreparedDefender:
        """Arm the defender and block until armed. Stand up the box ES and box agent, launch the single arm-then-loop runner, and block on its readiness marker. Returns the baton build_config() bakes."""
        experiment_name = experiment.experiment_name
        env_spec = experiment._defender_env_spec
        # Box ES + box agent (blocking SSH work, so run it off the event loop).
        box_cfg = {"defender_env_spec": env_spec.model_dump() if env_spec is not None else {},
                   "defender_setup_access": [a.model_dump() for a in (access or [])]}
        loop = asyncio.get_event_loop()
        es = await loop.run_in_executor(None, self.prepare_box_es, box_cfg, experiment_name, cfg)
        box_cfg.update(es)  # the box-agent config reads sysflow_index from prepare_box_es's output
        agent = await loop.run_in_executor(None, self.prepare_box_agent, box_cfg, experiment_name, cfg)
        # The env-action channel: the token'd TCP endpoint the arena armed on harness-loopback.
        _box_port = getattr(experiment, "_env_action_box_port", None)
        prepared = PreparedDeception(
            env_action_url=(f"http://127.0.0.1:{_box_port}" if _box_port else None),
            env_action_token=getattr(experiment, "_env_action_token", None),
            **{**es, **agent})
        # Write the runner config this method launches against (run_setup re-writes the same config).
        config_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        built = self.build_config(experiment_name, env_spec, prepared)
        if env_spec is not None:
            built["defender_env_spec"] = env_spec.model_dump()
        built["defender_setup_access"] = [a.model_dump() for a in (access or [])]
        built["management_ip"] = cfg.arena_host_ip
        built["bastion_ip"] = bastion_ip
        built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
        config_path.write_text(json.dumps(built, indent=2))
        # Arm: launch the single arm-then-loop runner and block until it signals armed. A failed arm exits
        # non-zero before the marker, which _wait_local_ready raises on, so an undefended run never reaches the attacker.
        self._clear_ready_marker(experiment_name, cfg)
        proc = await self._launch_runner(config_path, experiment_name, cfg)
        _PROCS[experiment_name] = proc
        await self._wait_local_ready(experiment_name, cfg, proc)
        return prepared


    async def teardown(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> None:
        # Kill the harness-host -> box ES ssh -L tunnel. (The environment's own teardown reaps stray decoy VMs.)
        self._teardown_box_es_tunnel(experiment_name, cfg)

    async def start(
        self,
        prepared: PreparedDefender,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """Hand run_start the arm-then-loop process launched and armed in setup(). Fallback: launch now if setup() did not run."""
        proc = _PROCS.pop(experiment_name, None)
        if proc is not None:
            return proc
        return await self._launch_runner(config_path, experiment_name, cfg)

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        # Fallback launcher (start() normally hands back the process launched in setup()).
        return await self._launch_runner(config_path, experiment_name, cfg)

    async def _launch_runner(
        self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """Launch this plugin's single arm-then-loop runner locally in the Perry venv and return the process."""
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        repo_dir = self._code_dir(cfg)
        pythonpath = os.pathsep.join(p for p in (str(repo_dir), os.environ.get("PYTHONPATH", "")) if p)
        return await asyncio.create_subprocess_exec(
            str(self._code_python(cfg)), str(Path(__file__).parent / "runner.py"), str(config_path),
            cwd=str(repo_dir), env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=open(log_path, "a"), stderr=subprocess.STDOUT,
        )

    # Readiness: setup() blocks until the runner signals armed. Copied per harness-run reactive defender, not a base method.
    @staticmethod
    def _ready_marker(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_ready"

    def _clear_ready_marker(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        try:
            self._ready_marker(experiment_name, cfg).unlink()
        except FileNotFoundError:
            pass

    async def _wait_local_ready(self, experiment_name: str, cfg: ExperimentManagerConfig, process,
                                timeout_s: float = 1800.0, poll_s: float = 2.0) -> float:
        """Block until the runner writes its readiness marker, then return seconds waited. Raises if the process dies first or arming exceeds timeout."""
        marker = self._ready_marker(experiment_name, cfg)
        start = time.monotonic()
        while True:
            if process.returncode is not None:
                raise RuntimeError(
                    f"defender runner exited (rc={process.returncode}) before arming — see defender.log")
            if marker.exists():
                return time.monotonic() - start
            if time.monotonic() - start > timeout_s:
                raise RuntimeError(f"defender did not arm within {timeout_s:.0f}s (no {marker})")
            await asyncio.sleep(poll_s)

    # Per-experiment Elasticsearch on the defender box: stand up ES on the box and tunnel to it, so each run
    # gets its own ES (no cross-experiment contamination). Copied into each telemetry-consuming plugin.
    @staticmethod
    def _es_tunnel_pidfile(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "es_tunnel.pid"

    # Box agent deploy (the defender's in-environment effector): ship the Perry runtime to the box, start the
    # agent on box:8900, open a harness -> box ssh -L tunnel, and inject the endpoint into the config. NOT YET LIVE-VALIDATED.
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

        # 1. ship only the ansible/ YAML tree + the standalone agent, via the bastion jump.
        rsync_e = "ssh " + " ".join(shlex.quote(o) for o in ssh_opts)
        subprocess.run(
            # never ship artifacts/ (ansible-runner's own output, which can grow to GBs and blow the timeout).
            ["rsync", "-a", "--delete", "-e", rsync_e, "--exclude", ".git", "--exclude", "__pycache__",
             "--exclude", "artifacts",
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
            # A decoy's SysFlow exports to the box's own ES at :9200. Plain HTTP, no auth. NOTE live-unknown: decoy->box:9200 routing.
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

    # Copied per box-using defender: pull the box agent's log off the box. Reaches the box by box ip from the
    # config, NOT primary_access (for a defender access[0] is a victim, so the passed access can't reach the box).
    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        """Best-effort: copy /root/box_agent.log off the defender box into dest/box_agent.log. Never raises."""
        import json as _json
        import os as _os
        import shlex
        try:
            exp = experiment.experiment_name
            cfg_path = output_root(exp, cfg) / exp / "defender" / "defender_config.json"
            if not cfg_path.exists():
                return
            built = _json.loads(cfg_path.read_text())
            box_ip = ((built.get("defender_env_spec") or {}).get("box") or {}).get("ip")
            if not box_ip:
                return
            box_acc = next((a for a in built.get("defender_setup_access", [])
                            if a.get("host") == box_ip), None)
            if not box_acc or not box_acc.get("ssh_key"):
                return
            key = _os.path.expanduser(box_acc["ssh_key"])
            common = shlex.split(box_acc.get("ssh_common_args") or "")
            user = box_acc.get("user", "root")
            port = str(box_acc.get("port", 22))
            ssh = ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                   "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", "-p", port, *common,
                   f"{user}@{box_ip}", "cat /root/box_agent.log"]
            dest.mkdir(parents=True, exist_ok=True)
            with (dest / "box_agent.log").open("wb") as out:
                proc = await asyncio.create_subprocess_exec(
                    *ssh, stdout=out, stderr=asyncio.subprocess.DEVNULL)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=60)
                except asyncio.TimeoutError:
                    proc.kill()
        except Exception:  # noqa: BLE001
            pass

    def prepare_box_es(self, box_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        """Install ES on the defender box (idempotent) and open a harness-host -> box:9200 ssh -L tunnel. Fail-closed: raises if there is no defender box."""
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

        # 1. ship + run the ES install (idempotent). Two steps so the stdin write completes before the channel closes.
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
