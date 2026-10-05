"""Box-RESIDENT variant of the LLM-SOC defender.

Where LLMSOCDefenderPlugin (executes_from_box) runs Perry's detection loop on the HARNESS host and reaches
the box ES over an ssh -L tunnel (+ a thin box agent for host actions), this plugin runs the WHOLE Perry
engine ON the defender box:

  * This plugin ships the Perry repo (+ its .env) to the box and provisions a uv standalone CPython-3.12 venv
    there (the box itself is py3.8), installs Perry's requirements, and runs the SAME llm_soc runner under it
    (its OWN copy of the box-launch unit, box_ships_engine mode). cwd + PYTHONPATH = the shipped engine.
  * The engine reads the per-experiment Elasticsearch at the box's OWN loopback (127.0.0.1:9200) — no harness
    ssh -L tunnel — and calls its LLM directly (the box has outbound internet; live-verified).
  * Its one cloud action, RestoreServer, is an INFRA action routed back to the ENVIRONMENT over an
    ssh -R reverse tunnel THIS PLUGIN opens (env_action_url + per-experiment token baked into the runner
    config), so the box still holds NO cloud credential. The plugin owns that tunnel exactly like the Incalmo
    attacker owns its ssh -L C2 tunnel: it opens it in start() and tears it down in stop(). The arena owns
    only the harness-side TCP env-action SERVER + the token/port (keyed on uses_env_actions), not the tunnel.

Pure FalcoLLM / FalcoLLMC2Block only: these deploy no decoys and need no box agent (FalcoLLM restores via the
env; C2Block's BlockIP is a host action that would need the agent — gate that later). Kept a SEPARATE plugin
(not a flag on llm_soc) so the live-validated harness-run llm_soc path is untouched. The box-launch machinery
is the FULL box-launch unit, copied onto this plugin (per the self-containment rule — the base no longer
carries it; canary carries the stdlib subset).
"""
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

# The plugin-owned ssh -R env-action tunnel procs, keyed by experiment_name. The plugin is a pydantic model
# that holds no runtime state, so (exactly like the Incalmo attacker keeps its C2/tunnel state OUTSIDE the
# plugin instance) the tunnel proc lives here: start() opens + records it, stop() pops + closes it. stop()
# runs on every teardown path (main.py's finally -> _stop_defender_process -> run_stop -> stop), so the
# tunnel is reaped reliably; a hard manager crash is the one residual (the same one Incalmo's ssh -L has).
_ENV_TUNNELS: dict = {}


class LLMSOCBoxDefenderPlugin(LLMSOCDefenderPlugin, config_type="llm_soc_box"):
    """LLM-SOC defender whose detection engine runs ON the defender box (see module docstring)."""

    type: Literal["llm_soc_box"]

    # This plugin's OWN copy of the box-launch unit (below) ships + runs the engine on the box, threading the
    # scoped creds at launch; its start()/stop() open and close the ssh -R env-action tunnel.
    #   uses_env_actions=True  -> the arena arms the token'd TCP env-action SERVER + the SERVING window + the
    #                             per-experiment token/port (NOT the tunnel — the plugin opens that itself).
    #   executes_from_box=False -> this is NOT the harness-run box-agent/UDS controller; it runs IN-env and
    #                             reaches the env ONLY over the plugin's ssh -R tunnel, and reaches victims
    #                             itself with the box-threaded keys (so it keeps the FULL victim access).
    #   box_python="3.12"      -> _box_run_command provisions a uv standalone CPython-3.12 venv (box is py3.8).
    #   box_ships_engine=True  -> _launch_on_box rsyncs the Perry repo (box_engine_src) and runs the runner
    #                             with cwd/PYTHONPATH = the shipped engine (box_pip_spec is unused in this mode).
    uses_env_actions: ClassVar[bool] = True
    executes_from_box: ClassVar[bool] = False
    box_python: ClassVar[Optional[str]] = "3.12"
    box_ships_engine: ClassVar[bool] = True
    _BOX_DIR: ClassVar[str] = "/opt/arena-defender"  # where the runner + config + uv venv + engine live on the box

    def box_engine_src(self, cfg: ExperimentManagerConfig) -> Optional[Path]:
        # The Perry/Defense repo for this plugin (code_dir_field = llm_soc_dir, inherited). Shipped to the box
        # (its .env rides along — langchain_registry loads <repo>/.env, which lands at the box engine root).
        return self._code_dir(cfg)

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        s = LLMSOCDefenderPlugin.ui_schema()
        s["config_type"] = "llm_soc_box"
        s["label"] = "LLM SOC (box-resident engine)"
        return s

    async def provision_box(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
        needs_agent: bool = False,
    ) -> PreparedLLMSOC:
        # Box-resident Phase A: stand up this run's per-experiment ES ON the box, but DON'T open a harness
        # ssh -L tunnel (the engine runs on the box and reads ES at box-loopback) and DON'T deploy the box
        # agent (FalcoLLM has no host actions; RestoreServer routes to the env over the ssh -R tunnel). The
        # baton hands build_config the box's OWN loopback es_url, which it bakes into the runner config.
        box_cfg = {
            "defender_env_spec": defender_env_spec.model_dump() if defender_env_spec is not None else {},
            "defender_setup_access": [a.model_dump() for a in (defender_access or [])],
        }
        loop = asyncio.get_event_loop()
        es = await loop.run_in_executor(None, self._install_box_es_only, box_cfg, experiment_name, cfg)
        return PreparedLLMSOC(
            es_url="http://127.0.0.1:9200",
            falco_index=es["falco_index"],
            sysflow_index=es["sysflow_index"],
        )

    def _install_box_es_only(self, box_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        """Install the per-experiment Elasticsearch ON the defender box (idempotent; box_es_install.sh binds
        0.0.0.0:9200, single-node). No ssh -L tunnel: the box-resident engine reads it at 127.0.0.1:9200 and
        the env relay ships sensor telemetry to box:9200. Reuses llm_soc's co-located box_es_install.sh."""
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
        # No harness-side ssh -L tunnel to kill (the engine ran on the box); ES dies with the box at env
        # teardown. The ssh -R env-action tunnel is reaped in stop() (keyed in _ENV_TUNNELS); close any
        # stray one here too, best-effort, in case stop() was skipped.
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
        """Open THIS PLUGIN's ssh -R env-action tunnel (box-loopback -> harness-loopback), then launch the
        engine ON THE BOX (overrides the base's local run()). The tunnel mirrors the Incalmo attacker's ssh -L
        C2 tunnel — the plugin owns it, not the arena: the arena armed the token'd TCP server + port (keyed
        on uses_env_actions) and baked env_action_url+token into the runner config; here we read that port
        back and open the reverse forward so the box engine's RestoreServer calls reach the harness server.

        TIMING NOTE: the tunnel opens HERE in start() (run_defender), i.e. AFTER setup()/prepare(). That is
        fine for a REACTIVE box-resident defender like FalcoLLM, whose prepare() is a no-op and whose env
        actions only fire once the run loop is live. A FUTURE box-resident DECOY defender that deploys decoys
        during prepare() (external arming) would need its env channel up BEFORE that — open its tunnel in
        provision_box()/setup() instead of here. (Our harness-run decoy defenders — deception / prompt_injection
        — don't hit this: they reach the env over the UDS, not this tunnel.)"""
        built = json.loads(Path(config_path).read_text())
        url = built.get("env_action_url")
        if url:  # uses_env_actions: arm the reverse tunnel BEFORE the engine so its env actions can route
            port = int(url.rsplit(":", 1)[1])
            box = self._select_box(access, built)
            tun_log = output_root(experiment_name, cfg) / experiment_name / "defender" / "env_action_tunnel.log"
            tun_log.parent.mkdir(parents=True, exist_ok=True)
            # open + confirm up; a failure RAISES -> fails the start (like a readiness gate). box_port ==
            # tcp_port (same loopback port both ends; distinct per box/experiment, so no collision).
            _ENV_TUNNELS[experiment_name] = await open_reverse_tunnel(box, port, port, log_path=tun_log)
        return await self._launch_on_box(prepared, config_path, experiment_name, cfg, access)

    async def stop(self, experiment, cfg: ExperimentManagerConfig, access=None) -> None:
        """Tear down the box engine (base SIGTERMs the local ssh -tt, which kills the remote session), THEN
        close the plugin-owned ssh -R tunnel. Runs on every teardown path (main.py finally ->
        _stop_defender_process -> run_stop -> stop)."""
        await super().stop(experiment, cfg, access=access)
        proc = _ENV_TUNNELS.pop(experiment.experiment_name, None)
        if proc is not None:
            await close_reverse_tunnel(proc)

    def _select_box(self, access, built: dict):
        """The defender-box DefenderSetupAccess. The access list is victims-first / box-last, so select the
        box by its ip (from the config's defender_env_spec); fall back to primary_access only if absent."""
        _box_ip = ((built.get("defender_env_spec") or {}).get("box") or {}).get("ip")
        box = next((a for a in access if str(getattr(a, "host", None)) == str(_box_ip)), None) if _box_ip else None
        return box if box is not None else self.primary_access(access)

    # ------------------------------------------------------------------ box launch (full unit)
    # The complete box-launch unit (uv venv + engine ship), copied onto this plugin (the base no longer
    # carries it; canary carries the control-plane-free stdlib subset). Command construction is PURE
    # (unit-testable); only the ship/ssh round-trips need a live box. Creds ride in `access` (threaded at
    # launch), NEVER in the shipped config; the config's log_dir is rewritten to a box path so the runner's
    # readiness marker lands on the box, which _wait_box_ready bridges to the local marker the arena polls.
    def _box_runner_src(self) -> Path:
        """This plugin's own runner.py, shipped to the box (kept next to the module, per self-containment)."""
        return Path(inspect.getfile(type(self))).parent / "runner.py"

    def _box_paths(self) -> dict:
        d = self._BOX_DIR
        return {"dir": d, "runner": f"{d}/runner.py", "config": f"{d}/defender_config.json",
                "venv": f"{d}/venv", "engine": f"{d}/engine", "log_dir": f"{d}/logs",
                "ready": f"{d}/logs/defender_ready"}

    def box_pip_spec(self) -> str:
        """What `uv pip install` installs for a uv-venv box engine. Unused in box_ships_engine mode (the
        engine installs from its own requirements.txt); kept for the unit's completeness. Raises so a
        misconfigured non-engine uv plugin fails loud, not silently bare."""
        raise NotImplementedError(
            f"{type(self).__name__} sets box_python={self.box_python!r} but does not override box_pip_spec() "
            "— a uv-venv box engine must declare what to install (see docs/agent-symmetry.md)")

    def _box_run_command(self) -> str:
        """PURE (no I/O — unit-testable): the remote shell command run over SSH to launch the box runner.
          box_python is None  -> run the shipped runner under the box's own python3 (stdlib runner).
          box_python == "3.N" -> install uv + a standalone CPython venv (Terminus pattern, sidesteps the box's
                                 broken apt + missing venv module) + the engine, then run under that venv.
        `exec` so the runner replaces the shell as the ssh session's process; with `ssh -tt` the local ssh
        pid then proxies it, so stop()'s local SIGTERM tears the box process down too."""
        p = self._box_paths()
        prelude = f"set -e; mkdir -p {shlex.quote(p['dir'])} {shlex.quote(p['log_dir'])}"
        if self.box_python is None:
            return f"{prelude}; exec python3 {shlex.quote(p['runner'])} {shlex.quote(p['config'])}"
        venv_py = p["venv"] + "/bin/python"
        # box_ships_engine: install the shipped repo's requirements.txt and run the runner with cwd +
        # PYTHONPATH = the shipped engine (the runner imports the repo's packages + reads its config/.env
        # relative to cwd). Otherwise: install the declared box_pip_spec() and run the lone stdlib-light runner.
        if self.box_ships_engine:
            install = f"uv pip install --python {shlex.quote(venv_py)} -r {shlex.quote(p['engine'] + '/requirements.txt')}"
            # Fail loud + EARLY if the box has no outbound internet (uv's CPython download, PyPI wheels, and
            # the engine's own LLM API calls all need it) — a precise exit beats a mid-run hang. Live-proven
            # green on the OpenStack estate; this is the regression guard.
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

    async def _ship_engine_to_box(self, base: list[str], paths: dict, cfg: ExperimentManagerConfig) -> None:
        """Rsync a box_ships_engine defender's engine tree (its code packages + requirements.txt + .env) to
        the box's engine dir, over the box's own ssh routing (the bastion ProxyCommand in ssh_base). Excludes
        .git/__pycache__/*.pyc and the heavy ansible/artifacts trees the box engine never uses (it routes
        infra actions to the env over the tunnel; it runs no ansible locally)."""
        src = self.box_engine_src(cfg)
        if src is None:
            raise RuntimeError(
                f"{type(self).__name__} sets box_ships_engine=True but box_engine_src() returned None")
        src = Path(src)
        engine_dir = paths["engine"]
        # ssh transport for rsync: ssh_base() minus the leading "ssh" and the trailing user@host target.
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

    async def _launch_on_box(self, prepared: "PreparedLLMSOC", config_path: Path, experiment_name: str,
                             cfg: ExperimentManagerConfig, access) -> "asyncio.subprocess.Process":
        """Launch the defender runner FROM THE BOX over SSH and return the ssh process (local pid proxies the
        remote). Mirrors the attacker's foothold bring-up (terminus/incalmo): ship the runner + config, then
        run it over `ssh -tt`. Credentials ride in `access` (threaded at launch), NEVER in the shipped config;
        the config's log_dir is rewritten to a box path so the runner's readiness marker lands on the box,
        which _wait_box_ready then bridges to the local marker the arena's wait_until_ready polls."""
        # ship the runner + a box-local copy of the config (log_dir -> box path; the runner writes its
        # defender_ready marker there). Everything else in the config is run-spec data, safe to ship.
        built = json.loads(Path(config_path).read_text())
        box = self._select_box(access, built)
        base = box.ssh_base()
        p = self._box_paths()
        built["log_dir"] = p["log_dir"]
        # box_ships_engine: rsync the plugin's engine tree (+ its .env) to the box FIRST, so _box_run_command
        # can install its requirements.txt into the uv venv and run the runner with cwd/PYTHONPATH = the engine.
        if self.box_ships_engine:
            await self._ship_engine_to_box(base, p, cfg)
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
        """Poll the box over SSH until the runner writes its readiness marker (the box analog of the local
        wait_until_ready poll / the attacker's wait_c2c_agent), then TOUCH the local marker so the arena's
        wait_until_ready passes unchanged. Raises if the box process dies first or the wait times out — an
        undefended run must never be reported defended. Returns seconds waited."""
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
        local = self.ready_marker_path(experiment_name, cfg)  # bridge: the arena polls the LOCAL marker
        local.parent.mkdir(parents=True, exist_ok=True)
        local.touch()
        return time.monotonic() - start
