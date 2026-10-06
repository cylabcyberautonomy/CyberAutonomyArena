"""Canary (diagnostic) defender — proves the defender-side plumbing works, then idles."""
from __future__ import annotations

import asyncio
import inspect
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import ClassVar, Literal, Optional

from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin, PreparedDefender

_ALL_CHECKS = ["ssh", "resolve", "telemetry", "canary_event"]
_BOX_PROCS: dict = {}


class CanaryDefenderPlugin(DefenderPlugin, config_type="canary"):
    """Diagnostic defender: verifies defender<->environment connectivity end to end."""

    type: Literal["canary"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "checks", "fail_closed"})
    _BOX_DIR: ClassVar[str] = "/opt/arena-defender"
    checks: list[str] = list(_ALL_CHECKS)
    canary_host: Optional[str] = None
    telemetry_port: int = 9200
    telemetry_timeout_s: float = 60.0
    fail_closed: bool = False

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "canary",
            "label": "Canary (connectivity diagnostic)",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Checks",
                    "key": "checks",
                    "options": list(_ALL_CHECKS),
                    "default": list(_ALL_CHECKS),
                },
                {
                    "field_type": "bool",
                    "label": "Fail closed (refuse to arm on a failed check)",
                    "key": "fail_closed",
                    "default": False,
                },
            ],
        }

    def box_ingress(self) -> dict[str, list[int]]:
        if any(c in self.checks for c in ("telemetry", "canary_event")):
            return {"telemetry": [9200]}
        return {}

    def build_config(
        self,
        experiment_name: str,
        env_spec=None,
        prepared=None,
    ) -> dict:
        built = {
            "experiment_name": experiment_name,
            "checks": self.checks,
            "canary_host": self.canary_host,
            "telemetry_port": self.telemetry_port,
            "telemetry_timeout_s": self.telemetry_timeout_s,
            "fail_closed": self.fail_closed,
        }
        return built

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            sys.executable,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> PreparedDefender:
        """Write the runner config, launch the canary on the box over SSH, and SSH-poll until it arms."""
        experiment_name = experiment.experiment_name
        env_spec = experiment._defender_env_spec
        config_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        built = self.build_config(experiment_name, env_spec, PreparedDefender())
        if env_spec is not None:
            built["defender_env_spec"] = env_spec.model_dump()
        built["defender_setup_access"] = [a.model_dump() for a in (access or [])]
        built["management_ip"] = cfg.arena_host_ip
        built["bastion_ip"] = bastion_ip
        built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
        config_path.write_text(json.dumps(built, indent=2))
        _BOX_PROCS[experiment_name] = await self._launch_on_box(
            PreparedDefender(), config_path, experiment_name, cfg, access)
        return PreparedDefender()

    async def start(
        self,
        prepared: "PreparedDefender",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """Hand run_start the canary process launched in setup(). Fallback: launch it now."""
        proc = _BOX_PROCS.pop(experiment_name, None)
        if proc is not None:
            return proc
        return await self._launch_on_box(prepared, config_path, experiment_name, cfg, access)

    def _box_runner_src(self) -> Path:
        """This plugin's own runner.py, shipped to the box."""
        return Path(inspect.getfile(type(self))).parent / "runner.py"

    def _box_paths(self) -> dict:
        d = self._BOX_DIR
        return {"dir": d, "runner": f"{d}/runner.py", "config": f"{d}/defender_config.json",
                "log_dir": f"{d}/logs", "ready": f"{d}/logs/defender_ready"}

    def _box_run_command(self) -> str:
        """The remote shell command run over SSH to launch the box runner under the box's python3."""
        p = self._box_paths()
        prelude = f"set -e; mkdir -p {shlex.quote(p['dir'])} {shlex.quote(p['log_dir'])}"
        return f"{prelude}; exec python3 {shlex.quote(p['runner'])} {shlex.quote(p['config'])}"

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

    async def _launch_on_box(self, prepared: "PreparedDefender", config_path: Path, experiment_name: str,
                             cfg: ExperimentManagerConfig, access) -> "asyncio.subprocess.Process":
        """Ship the runner + config to the box and launch it over `ssh -tt`, returning the ssh process."""
        built = json.loads(Path(config_path).read_text())
        _box_ip = ((built.get("defender_env_spec") or {}).get("box") or {}).get("ip")
        box = next((a for a in access if str(getattr(a, "host", None)) == str(_box_ip)), None) if _box_ip else None
        if box is None:
            box = self.primary_access(access)
        base = box.ssh_base()
        p = self._box_paths()
        built["log_dir"] = p["log_dir"]
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
