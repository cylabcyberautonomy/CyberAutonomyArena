"""Canary (diagnostic) defender — proves the defender-side plumbing works, then idles.

It deploys no decoys, calls no LLM, needs no Elasticsearch client library, no Perry repo and
no OpenStack SDK. Its runner is stdlib-only (SSH via subprocess, ES via urllib). So when it
fails you know the failure is *connectivity*, not detection logic; when it passes you know a
real defender could connect on this environment.

Checks (any subset via `checks`):
  ssh           - SSH through the bastion to every victim (using the SetupAccess the environment
                  produced: per-host key + routing), run `hostname`
  resolve       - compare each victim's real OS hostname to its DefenderEnvSpec model-name (the
                  FalcoLLM hostname-resolution trap: model 'webserver0' vs OS 'host2')
  telemetry     - GET <management_ip>:<port>/_cat/indices and confirm this run's
                  falco-<exp>/sysflow-<exp> indices exist (the same ES a real defender reads)
  canary_event  - read /etc/shadow on a victim, then confirm a new event lands in the falco
                  index within telemetry_timeout_s (proves victim -> sensor -> store -> reader)

`fail_closed: false` (default) always arms and just reports; `true` refuses to arm if a
required check fails, turning the canary into a hard gate.

The canary reads its hosts and per-host SSH access from the arena-produced DefenderEnvSpec +
SetupAccess (injected into its config by run_defender); it does not resolve an MHBench SSH key or
parse the topology itself.
"""
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


class CanaryDefenderPlugin(DefenderPlugin, config_type="canary"):
    """Diagnostic defender: verifies defender<->environment connectivity end to end."""

    type: Literal["canary"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "checks", "fail_closed"})
    # Run ON THE BOX: the canary is the control-plane-free, stdlib-only proof of the box launch — it ships
    # its runner to the box and runs it under the box's own python3, reaching victims with the box-threaded
    # scoped key. No uv, no engine tree, no env-action channel. The box-launch machinery is the STDLIB
    # SUBSET of the box-launch unit, copied onto this plugin (per the self-containment rule — the base no
    # longer carries it); uses_env_actions stays False (base default), so the arena arms no env channel.
    _BOX_DIR: ClassVar[str] = "/opt/arena-defender"  # where the runner + config live on the box
    checks: list[str] = list(_ALL_CHECKS)
    canary_host: Optional[str] = None       # victim name/role for the canary_event read; None = first victim
    telemetry_port: int = 9200
    telemetry_timeout_s: float = 60.0
    fail_closed: bool = False               # True = refuse to arm if a required check fails

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
        # Only the telemetry/canary_event checks touch the box ES; ssh/resolve-only opens nothing.
        if any(c in self.checks for c in ("telemetry", "canary_event")):
            return {"telemetry": [9200]}
        return {}

    def build_config(
        self,
        experiment_name: str,
        env_spec=None,
        prepared=None,  # Phase-A baton; canary has no box telemetry, so it is unused
    ) -> dict:
        # Only the plugin-specific knobs here; the standard runner keys (defender_env_spec, defender_setup_access,
        # management_ip, bastion_ip, log_dir, ...) are forwarded by the framework (run_setup) after this.
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
        # stdlib-only runner: use the manager's own interpreter, no special PYTHONPATH/cwd.
        return await asyncio.create_subprocess_exec(
            sys.executable,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    async def start(
        self,
        prepared: "PreparedDefender",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """Launch the canary ON THE BOX over SSH (overrides the base's local run()). Ships the stdlib runner
        + a box-local config, threads the scoped keys to the box, and runs it under the box's own python3."""
        return await self._launch_on_box(prepared, config_path, experiment_name, cfg, access)

    # ------------------------------------------------------------------ box launch (stdlib subset)
    # The control-plane-free subset of the box-launch unit (the full unit — uv venv + engine ship + the
    # ssh -R env channel — lives on llm_soc_box). Command construction is PURE (unit-testable); only the
    # ship/ssh round-trips need a live box. Creds ride in `access` (threaded at launch), NEVER in the
    # shipped config; the config's log_dir is rewritten to a box path so the runner's readiness marker lands
    # on the box, which _wait_box_ready then bridges to the local marker the arena's wait_until_ready polls.
    def _box_runner_src(self) -> Path:
        """This plugin's own runner.py, shipped to the box (kept next to the module, per self-containment)."""
        return Path(inspect.getfile(type(self))).parent / "runner.py"

    def _box_paths(self) -> dict:
        d = self._BOX_DIR
        return {"dir": d, "runner": f"{d}/runner.py", "config": f"{d}/defender_config.json",
                "log_dir": f"{d}/logs", "ready": f"{d}/logs/defender_ready"}

    def _box_run_command(self) -> str:
        """PURE (no I/O — unit-testable): the remote shell command run over SSH to launch the box runner
        under the box's own python3 (the canary runner is stdlib-only). `exec` so the runner replaces the
        shell as the ssh session's process; with `ssh -tt` the local ssh pid proxies it, so stop()'s local
        SIGTERM tears the box process down too."""
        p = self._box_paths()
        prelude = f"set -e; mkdir -p {shlex.quote(p['dir'])} {shlex.quote(p['log_dir'])}"
        return f"{prelude}; exec python3 {shlex.quote(p['runner'])} {shlex.quote(p['config'])}"

    @staticmethod
    def _tty_ssh(base: list[str]) -> list[str]:
        """Insert `-tt` right after `ssh` so the remote process is bound to the ssh session: the LOCAL ssh
        pid proxies the remote runner, so stop()'s SIGTERM to the local pid tears the box process down too."""
        return [base[0], "-tt", *base[1:]]

    async def _box_push(self, base: list[str], remote_path: str, content: str, mode: Optional[str] = None) -> None:
        """Write `content` to `remote_path` on the box over the box's ssh access (no scp dependency). `mode`
        (e.g. "600") chmods it after — used for shipped key files."""
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
        """PURE (unit-testable): return access entries with ssh_key AND the `-i <key>` path inside
        ssh_common_args (the bastion ProxyCommand) rewritten per key_map (harness path -> box path), so a
        box-resident runner reaches victims with keys that exist on the box."""
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
        """Thread the scoped creds to the box: ship each UNIQUE key the access entries reference to a
        box-local path (chmod 600), then return the entries rewritten to reference the box-local keys. The
        box runner then reaches victims/box with keys that exist ON THE BOX, not harness paths."""
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
        """Launch the runner FROM THE BOX over SSH and return the ssh process (local pid proxies the remote).
        Mirrors the attacker's foothold bring-up: ship the runner + config, then run it over `ssh -tt`."""
        built = json.loads(Path(config_path).read_text())
        # Reach the DEFENDER BOX specifically — the access list is victims-first, box-last, so primary_access
        # ([0]) is a VICTIM. Select the box by its ip (already in the config's defender_env_spec); fall back
        # to primary_access only if the box ip is somehow absent (older single-subnet topologies).
        _box_ip = ((built.get("defender_env_spec") or {}).get("box") or {}).get("ip")
        box = next((a for a in access if str(getattr(a, "host", None)) == str(_box_ip)), None) if _box_ip else None
        if box is None:
            box = self.primary_access(access)
        base = box.ssh_base()
        p = self._box_paths()
        built["log_dir"] = p["log_dir"]
        # thread the scoped creds to the box (ship keys + rewrite the access paths to box-local copies) so
        # the box runner reaches victims with keys that exist on the box, not harness paths.
        if built.get("defender_setup_access"):
            built["defender_setup_access"] = await self._thread_box_credentials(
                base, p, built["defender_setup_access"])
        await self._box_push(base, p["runner"], self._box_runner_src().read_text())
        await self._box_push(base, p["config"], json.dumps(built))
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")  # noqa: SIM115 — handed to the long-running subprocess
        proc = await asyncio.create_subprocess_exec(
            *self._tty_ssh(base), self._box_run_command(),
            stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
        # block until the box runner arms, then bridge its box marker to the local one (main.py's
        # wait_until_ready stays untouched — it keeps polling the local marker).
        await self._wait_box_ready(experiment_name, cfg, box, proc)
        return proc

    async def _wait_box_ready(self, experiment_name: str, cfg: ExperimentManagerConfig, box, process,
                              timeout_s: float = 600.0, poll_s: float = 5.0) -> float:
        """Poll the box over SSH until the runner writes its readiness marker, then TOUCH the local marker so
        the arena's wait_until_ready passes unchanged. Raises if the box process dies first or the wait times
        out — an undefended run must never be reported defended. Returns seconds waited."""
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
        # The box runner is armed. No local-marker bridge any more (the arena's readiness handshake is gone —
        # run_setup emits READY once this returns). FOLLOW-UP: this launch+wait should move into setup() so
        # READY is emitted after the box arms; today it still runs in start() (acceptable on the set-aside
        # box-resident line).
        return time.monotonic() - start
