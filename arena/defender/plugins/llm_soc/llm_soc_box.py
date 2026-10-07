"""Box-resident variant of the LLM-SOC defender: the whole Perry engine runs on the defender box."""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import ClassVar, Literal, Optional

from ....config import ExperimentManagerConfig
from ....env_action_server import close_reverse_tunnel, open_reverse_tunnel
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from .llm_soc import LLMSOCDefenderPlugin, PreparedLLMSOC, _LLM_MODEL_SUGGESTIONS

_ENV_TUNNELS: dict = {}
_BOX_PROCS: dict = {}


class LLMSOCBoxDefenderPlugin(LLMSOCDefenderPlugin, config_type="llm_soc_box"):
    """LLM-SOC defender whose detection engine runs ON the defender box."""

    type: Literal["llm_soc_box"]

    uses_env_actions: ClassVar[bool] = True
    box_python: ClassVar[Optional[str]] = "3.12"
    box_ships_engine: ClassVar[bool] = True
    _BOX_DIR: ClassVar[str] = "/opt/arena-defender"

    def box_engine_src(self, cfg: ExperimentManagerConfig) -> Optional[Path]:
        return self._code_dir(cfg)

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        s = LLMSOCDefenderPlugin.ui_schema()
        s["config_type"] = "llm_soc_box"
        s["label"] = "LLM SOC (box-resident engine)"
        return s

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> PreparedLLMSOC:
        """Stand up box ES, write the config, open the ssh -R env-action tunnel, then launch the engine on the box and block until armed."""
        experiment_name = experiment.experiment_name
        env_spec = experiment._defender_env_spec
        box_cfg = {"defender_env_spec": env_spec.model_dump() if env_spec is not None else {},
                   "defender_setup_access": [a.model_dump() for a in (access or [])]}
        loop = asyncio.get_event_loop()
        es = await loop.run_in_executor(None, self._install_box_es_only, box_cfg, experiment_name, cfg)
        _box_port = getattr(experiment, "_env_action_box_port", None)
        prepared = PreparedLLMSOC(
            es_url="http://127.0.0.1:9200", falco_index=es["falco_index"], sysflow_index=es["sysflow_index"],
            env_action_url=(f"http://127.0.0.1:{_box_port}" if _box_port else None),
            env_action_token=getattr(experiment, "_env_action_token", None))
        # Write the runner config the box engine reads. build_config bakes the baton. Inject creds/routing,
        # which the leak guard keeps out of build_config, same as the base's run_setup.
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
        if built.get("env_action_url"):
            port = int(built["env_action_url"].rsplit(":", 1)[1])
            box = self._select_box(access, built)
            tun_log = output_root(experiment_name, cfg) / experiment_name / "defender" / "env_action_tunnel.log"
            tun_log.parent.mkdir(parents=True, exist_ok=True)
            _ENV_TUNNELS[experiment_name] = await open_reverse_tunnel(box, port, port, log_path=tun_log)
        _BOX_PROCS[experiment_name] = await self._launch_on_box(prepared, config_path, experiment_name, cfg, access)
        return prepared

    def _install_box_es_only(self, box_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        """Install the per-experiment Elasticsearch on the defender box (read at box-loopback 127.0.0.1:9200)."""
        import time

        box = (box_cfg.get("defender_env_spec") or {}).get("box") or {}
        box_ip = box.get("ip")
        if not box_ip:
            raise RuntimeError("no defender box in defender_env_spec; box ES is required (no fallback)")
        access = next((a for a in box_cfg.get("defender_setup_access", []) if a.get("host") == box_ip), None)
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
        return {"falco_index": "falco", "sysflow_index": "sysflow"}

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        proc = _ENV_TUNNELS.pop(experiment_name, None)
        if proc is not None:
            await close_reverse_tunnel(proc)
        return None

    async def start(
        self,
        prepared: "PreparedLLMSOC",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """Hand run_start the box runner process launched in setup(). Fallback: open the tunnel, then launch it now."""
        proc = _BOX_PROCS.pop(experiment_name, None)
        if proc is not None:
            return proc
        built = json.loads(Path(config_path).read_text())
        url = built.get("env_action_url")
        if url and experiment_name not in _ENV_TUNNELS:
            port = int(url.rsplit(":", 1)[1])
            box = self._select_box(access, built)
            tun_log = output_root(experiment_name, cfg) / experiment_name / "defender" / "env_action_tunnel.log"
            tun_log.parent.mkdir(parents=True, exist_ok=True)
            _ENV_TUNNELS[experiment_name] = await open_reverse_tunnel(box, port, port, log_path=tun_log)
        return await self._launch_on_box(prepared, config_path, experiment_name, cfg, access)

    async def stop(self, experiment, cfg: ExperimentManagerConfig, access=None) -> None:
        """Tear down the box engine, then close the plugin-owned ssh -R tunnel."""
        await super().stop(experiment, cfg, access=access)
        proc = _ENV_TUNNELS.pop(experiment.experiment_name, None)
        if proc is not None:
            await close_reverse_tunnel(proc)

    def _select_box(self, access, built: dict):
        """The defender-box DefenderSetupAccess, selected by box ip. Falls back to primary_access."""
        _box_ip = ((built.get("defender_env_spec") or {}).get("box") or {}).get("ip")
        box = next((a for a in access if str(getattr(a, "host", None)) == str(_box_ip)), None) if _box_ip else None
        return box if box is not None else self.primary_access(access)

    def _box_runner_src(self) -> Path:
        """This plugin's own runner.py, shipped to the box."""
        return Path(inspect.getfile(type(self))).parent / "runner.py"

    def _box_paths(self) -> dict:
        d = self._BOX_DIR
        return {"dir": d, "runner": f"{d}/runner.py", "config": f"{d}/defender_config.json",
                "venv": f"{d}/venv", "engine": f"{d}/engine", "log_dir": f"{d}/logs",
                "ready": f"{d}/logs/defender_ready"}

    def box_pip_spec(self) -> str:
        """What `uv pip install` installs for a uv-venv box engine (unused in box_ships_engine mode)."""
        raise NotImplementedError(
            f"{type(self).__name__} sets box_python={self.box_python!r} but does not override box_pip_spec() "
            "— a uv-venv box engine must declare what to install (see docs/agent-symmetry.md)")

    def _box_run_command(self) -> str:
        """The remote shell command run over SSH to launch the box runner (stdlib python3 or a uv venv)."""
        p = self._box_paths()
        prelude = f"set -e; mkdir -p {shlex.quote(p['dir'])} {shlex.quote(p['log_dir'])}"
        if self.box_python is None:
            return f"{prelude}; exec python3 {shlex.quote(p['runner'])} {shlex.quote(p['config'])}"
        venv_py = p["venv"] + "/bin/python"
        if self.box_ships_engine:
            install = f"uv pip install --python {shlex.quote(venv_py)} -r {shlex.quote(p['engine'] + '/requirements.txt')}"
            preflight = ("curl -sf -m 25 -o /dev/null https://pypi.org/simple/ || "
                         "{ echo 'BOX EGRESS FAIL: no route to pypi.org — a box-resident engine needs outbound internet'; exit 3; }; ")
            run = (f"cd {shlex.quote(p['engine'])}; exec env PYTHONPATH={shlex.quote(p['engine'])} "
                   f"{shlex.quote(venv_py)} {shlex.quote(p['runner'])} {shlex.quote(p['config'])}")
        else:
            install = f"uv pip install --python {shlex.quote(venv_py)} {self.box_pip_spec()}"
            preflight = ""
            run = f"exec {shlex.quote(venv_py)} {shlex.quote(p['runner'])} {shlex.quote(p['config'])}"
        boot = (
            "export PATH=$HOME/.local/bin:$PATH; "
            f"{preflight}"
            "command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh; "
            "export PATH=$HOME/.local/bin:$PATH; "
            f"test -d {shlex.quote(p['venv'])} || uv venv {shlex.quote(p['venv'])} --python {shlex.quote(self.box_python)}; "
            f"{install}"
        )
        return f"{prelude}; {boot}; {run}"

    @staticmethod
    def _tty_ssh(base: list[str]) -> list[str]:
        """Insert `-tt` after `ssh` so the local ssh pid proxies the remote process (SIGTERM-propagating)."""
        return [base[0], "-tt", *base[1:]]

    async def _box_push(self, base: list[str], remote_path: str, content: str, mode: Optional[str] = None) -> None:
        """Write `content` to `remote_path` on the box over ssh. `mode` chmods it after."""
        chmod = f" && chmod {mode} {shlex.quote(remote_path)}" if mode else ""
        proc = await asyncio.create_subprocess_exec(
            *base,
            f"mkdir -p {shlex.quote(str(Path(remote_path).parent))} && cat > {shlex.quote(remote_path)}{chmod}",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await asyncio.wait_for(proc.communicate(content.encode()), timeout=120)
        if proc.returncode != 0:
            raise RuntimeError(f"shipping {remote_path} to the box failed: {err.decode()[-400:]}")

    async def _ship_engine_to_box(self, base: list[str], paths: dict, cfg: ExperimentManagerConfig) -> None:
        """Rsync the engine tree (code + requirements.txt + .env) to the box's engine dir over its ssh routing."""
        src = self.box_engine_src(cfg)
        if src is None:
            raise RuntimeError(
                f"{type(self).__name__} sets box_ships_engine=True but box_engine_src() returned None")
        src = Path(src)
        engine_dir = paths["engine"]
        ssh_e = "ssh " + " ".join(shlex.quote(o) for o in base[1:-1])
        target = base[-1]
        mk = await asyncio.create_subprocess_exec(
            *base, f"mkdir -p {shlex.quote(engine_dir)}",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, mkerr = await asyncio.wait_for(mk.communicate(), timeout=60)
        if mk.returncode != 0:
            raise RuntimeError(f"creating engine dir on box failed: {mkerr.decode()[-300:]}")
        proc = await asyncio.create_subprocess_exec(
            "rsync", "-a", "--delete", "-e", ssh_e,
            "--exclude", ".git", "--exclude", "__pycache__", "--exclude", "*.pyc",
            "--exclude", "artifacts", "--exclude", "ansible",
            f"{str(src).rstrip('/')}/", f"{target}:{engine_dir}/",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await asyncio.wait_for(proc.communicate(), timeout=600)
        if proc.returncode != 0:
            raise RuntimeError(f"shipping engine tree to the box failed: {err.decode()[-400:]}")

    @staticmethod
    def _rewrite_access_keys(access_entries: list, key_map: dict) -> list:
        """Return access entries with ssh_key and the ProxyCommand key path rewritten per key_map."""
        out = []
        for entry in access_entries:
            e = dict(entry)
            k = e.get("ssh_key")
            if k in key_map:
                e["ssh_key"] = key_map[k]
                if e.get("ssh_common_args"):
                    e["ssh_common_args"] = e["ssh_common_args"].replace(k, key_map[k])
            out.append(e)
        return out

    async def _thread_box_credentials(self, base: list[str], paths: dict, access_entries: list) -> list:
        """Ship each unique key to a box-local path and return the entries rewritten to reference them."""
        import os as _os
        key_dir = f"{paths['dir']}/keys"
        key_map: dict = {}
        for entry in access_entries:
            k = entry.get("ssh_key")
            if k and k not in key_map:
                src = Path(_os.path.expanduser(k))
                box_key = f"{key_dir}/{src.name}"
                await self._box_push(base, box_key, src.read_text(), mode="600")
                key_map[k] = box_key
        return self._rewrite_access_keys(access_entries, key_map)

    async def _launch_on_box(self, prepared: "PreparedLLMSOC", config_path: Path, experiment_name: str,
                             cfg: ExperimentManagerConfig, access) -> "asyncio.subprocess.Process":
        """Ship the runner + config (+ engine) to the box and launch it over `ssh -tt`, returning the ssh process."""
        built = json.loads(Path(config_path).read_text())
        box = self._select_box(access, built)
        base = box.ssh_base()
        p = self._box_paths()
        built["log_dir"] = p["log_dir"]
        if self.box_ships_engine:
            await self._ship_engine_to_box(base, p, cfg)
        if built.get("defender_setup_access"):
            built["defender_setup_access"] = await self._thread_box_credentials(
                base, p, built["defender_setup_access"])
        await self._box_push(base, p["runner"], self._box_runner_src().read_text())
        await self._box_push(base, p["config"], json.dumps(built))
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")  # noqa: SIM115
        proc = await asyncio.create_subprocess_exec(
            *self._tty_ssh(base), self._box_run_command(),
            stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
        await self._wait_box_ready(experiment_name, cfg, box, proc)
        return proc

    async def _wait_box_ready(self, experiment_name: str, cfg: ExperimentManagerConfig, box, process,
                              timeout_s: float = 600.0, poll_s: float = 5.0) -> float:
        """Poll the box over SSH until the runner writes its readiness marker. Raise on process death or timeout."""
        p = self._box_paths()
        base = box.ssh_base()
        start = time.monotonic()
        while True:
            if process.returncode is not None:
                raise RuntimeError(
                    f"box defender process exited (rc={process.returncode}) before arming — see defender.log")
            check = await asyncio.create_subprocess_exec(
                *base, f"test -f {shlex.quote(p['ready'])} && echo READY || true",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(check.communicate(), timeout=poll_s * 4)
            if b"READY" in out:
                break
            if time.monotonic() - start > timeout_s:
                raise RuntimeError(f"box defender did not arm within {timeout_s:.0f}s (no {p['ready']})")
            await asyncio.sleep(poll_s)
        return time.monotonic() - start
