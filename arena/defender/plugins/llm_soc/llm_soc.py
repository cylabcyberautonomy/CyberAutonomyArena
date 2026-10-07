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

_PROCS: dict = {}

_LLM_MODEL_SUGGESTIONS = [
    "openrouter/anthropic/claude-sonnet-5",
    "openrouter/anthropic/claude-sonnet-4.5",
    "litellm/us.anthropic.claude-sonnet-5",
    "litellm/us.anthropic.claude-haiku-4-5-20251001",
    "litellm/gpt-5",
    "litellm/gemini/gemini-2.5-pro",
    "openrouter/openai/gpt-5",
    "openrouter/moonshotai/kimi-k2",
    "openrouter/qwen/qwen3-235b-a22b-2507",
    "openrouter/z-ai/glm-4.5",
    "claude-3.7-sonnet",
    "claude-3.7-thinking",
    "claude-3.5-sonnet",
    "claude-3.5-haiku",
    "claude-3-opus",
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-o1",
    "gemini-2.5-pro",
    "gemini-2-flash",
]


class PreparedLLMSOC(PreparedDefender):
    """llm_soc's box-telemetry baton: box ES tunnel + falco/sysflow indices + box-agent endpoint."""
    es_url: Optional[str] = None
    falco_index: Optional[str] = None
    sysflow_index: Optional[str] = None
    box_agent_host: Optional[str] = None
    box_agent_port: Optional[int] = None
    box_agent_token: Optional[str] = None
    env_action_url: Optional[str] = None
    env_action_token: Optional[str] = None


class LLMSOCDefenderPlugin(DefenderPlugin, config_type="llm_soc"):
    """Wraps Perry's LLM-SOC-analyst strategies. FalcoLLM restores a confirmed host. FalcoLLMC2Block blocks its C2 IP."""

    type: Literal["llm_soc"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "strategy", "llm_model"})
    code_dir_field = "llm_soc_dir"
    uses_env_actions = True
    code_python_field = "llm_soc_python"
    strategy: str
    llm_model: str = "openrouter/anthropic/claude-sonnet-5"

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value):
        if isinstance(value, list):
            return value[0] if value else "FalcoLLM"
        return value

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "llm_soc",
            "label": "LLM SOC",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Strategy",
                    "key": "strategy",
                    "options": ["FalcoLLM", "FalcoLLMC2Block"],
                    "short_names": {
                        "FalcoLLM": "falco_llm",
                        "FalcoLLMC2Block": "falco_c2blk",
                    },
                },
                {
                    "field_type": "text_with_suggestions",
                    "label": "LLM model (litellm/<model> or openrouter/<model-slug> recommended)",
                    "key": "llm_model",
                    "suggestions": _LLM_MODEL_SUGGESTIONS,
                    "default": "openrouter/anthropic/claude-sonnet-5",
                },
            ],
        }

    def box_ingress(self) -> dict[str, list[int]]:
        return {"telemetry": [9200]}

    def build_config(
        self,
        experiment_name: str,
        env_spec,
        prepared: PreparedDefender,
    ) -> dict:
        built = {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "llm_model": self.llm_model,
        }
        built.update({k: v for k, v in prepared.model_dump().items() if v is not None})
        return built

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> PreparedDefender:
        """Stand up box ES + box agent, write the config, then launch the arm-then-loop runner and block until armed."""
        experiment_name = experiment.experiment_name
        env_spec = experiment._defender_env_spec
        box_cfg = {"defender_env_spec": env_spec.model_dump() if env_spec is not None else {},
                   "defender_setup_access": [a.model_dump() for a in (access or [])]}
        loop = asyncio.get_event_loop()
        es = await loop.run_in_executor(None, self.prepare_box_es, box_cfg, experiment_name, cfg)
        box_cfg.update(es)
        agent = await loop.run_in_executor(None, self.prepare_box_agent, box_cfg, experiment_name, cfg)
        _box_port = getattr(experiment, "_env_action_box_port", None)
        prepared = PreparedLLMSOC(
            env_action_url=(f"http://127.0.0.1:{_box_port}" if _box_port else None),
            env_action_token=getattr(experiment, "_env_action_token", None),
            **{**es, **agent})
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
        self._clear_ready_marker(experiment_name, cfg)
        proc = await self._launch_runner(config_path, experiment_name, cfg)
        _PROCS[experiment_name] = proc
        await self._wait_local_ready(experiment_name, cfg, proc)
        return prepared

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

        rsync_e = "ssh " + " ".join(shlex.quote(o) for o in ssh_opts)
        subprocess.run(
            ["rsync", "-a", "--delete", "-e", rsync_e, "--exclude", ".git", "--exclude", "__pycache__",
             "--exclude", "artifacts",
             repo_dir.rstrip("/") + "/ansible/", f"{target}:/root/ansible/"],
            check=True, timeout=600)
        agent_src = Path(repo_dir) / "defender" / "box_agent" / "agent.py"
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_agent.py"],
                       input=agent_src.read_text(), text=True, check=True, timeout=60)
        subprocess.run([*ssh_base, target, "cat > /root/scoped_key && chmod 600 /root/scoped_key"],
                       input=Path(key).read_text(), text=True, check=True, timeout=60)
        token = secrets.token_urlsafe(24)
        box_cfg = {
            "token": token, "host": "127.0.0.1", "port": 8900,
            "ssh_key_path": "/root/scoped_key", "ansible_dir": "/root/ansible", "log_dir": "/root",
            "es_address": f"http://{box_ip}:9200",
            "es_index": cfgd.get("sysflow_index", "sysflow"),
        }
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_config.json"],
                       input=_json.dumps(box_cfg), text=True, check=True, timeout=60)
        script = (Path(__file__).parent / "box_agent_install.sh").read_text()
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_install.sh && chmod +x /root/box_agent_install.sh"],
                       input=script, text=True, check=True, timeout=60)
        subprocess.run([*ssh_base, target, "/root/box_agent_install.sh"], check=True, timeout=600)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            lport = s.getsockname()[1]
        tunnel = subprocess.Popen([*ssh_base, "-N", "-L", f"{lport}:localhost:8900", target],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pidfile = self._box_agent_tunnel_pidfile(experiment_name, cfg)
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(tunnel.pid))
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
        return {"box_agent_host": "127.0.0.1", "box_agent_port": lport, "box_agent_token": token}

    # Copied per box-using defender (self-contained, like prepare_box_agent/prepare_box_es): pull the box
    # agent's log off the box so a box-side failure is diagnosable after teardown. Reaches the box the SAME
    # way prepare_box_agent does — box ip from the persisted config's defender_env_spec.box.ip, its
    # scoped-access entry from defender_setup_access. NOT primary_access: for a defender access[0] is a
    # VICTIM (victims-first/box-last), so the passed `access` can't reach the box.
    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        """Best-effort: copy /root/box_agent.log off the defender box into dest/box_agent.log. Never raises —
        a missing box/log/tunnel must not fail the run's teardown."""
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
        except Exception:  # noqa: BLE001 — box-log collection is best-effort; never fail teardown
            pass

    async def teardown(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> None:
        self._teardown_box_es_tunnel(experiment_name, cfg)

    async def start(
        self,
        prepared: PreparedDefender,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """Hand run_start the arm-then-loop process launched in setup(). Fallback: launch it now."""
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
        return await self._launch_runner(config_path, experiment_name, cfg)

    async def _launch_runner(
        self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """Launch this plugin's single arm-then-loop runner locally in the Perry venv and return the process
        (spawned with cwd + PYTHONPATH = the Perry repo, so the runner imports it)."""
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        repo_dir = self._code_dir(cfg)
        pythonpath = os.pathsep.join(p for p in (str(repo_dir), os.environ.get("PYTHONPATH", "")) if p)
        return await asyncio.create_subprocess_exec(
            str(self._code_python(cfg)),
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            cwd=str(repo_dir),
            env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

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
        """Block until the runner writes its readiness marker. Raise on process death or timeout."""
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

    @staticmethod
    def _es_tunnel_pidfile(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "es_tunnel.pid"

    def prepare_box_es(self, box_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        """Install ES on the defender box and open a harness->box:9200 ssh -L tunnel. Returns es_url + indices."""
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

        script = (Path(__file__).parent / "box_es_install.sh").read_text()
        subprocess.run([*ssh_base, target, "cat > /root/box_es_install.sh && chmod +x /root/box_es_install.sh"],
                       input=script, text=True, check=True, timeout=60)
        subprocess.run([*ssh_base, target,
                        "nohup /root/box_es_install.sh > /root/es_install.log 2>&1 & echo launched"],
                       check=True, timeout=30)
        deadline = time.time() + 300
        while time.time() < deadline:
            r = subprocess.run([*ssh_base, target, "curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:9200"],
                               capture_output=True, text=True, timeout=30)
            if r.stdout.strip() == "200":
                break
            time.sleep(10)
        else:
            raise RuntimeError(f"defender-box ES did not come up on {box_ip}:9200 within 300s")

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
