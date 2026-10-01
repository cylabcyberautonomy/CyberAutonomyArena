import asyncio
import os
import subprocess
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...experiment_log import output_root
from ...environment import DeployedEnvironment
from ...ui_schema import PluginUISchema


class DefenderPlugin(BaseModel):
    _registry: ClassVar[dict[str, type["DefenderPlugin"]]] = {}

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            DefenderPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    def box_ingress(self) -> dict[str, list[int]]:
        """The defender-requested box-ingress this plugin needs the ENVIRONMENT to open, by kind:

            "telemetry": [9200]  -> the env relay routes sensor telemetry to the box ES on these
                                    ports (no new victim-facing firewall port opens).
            "forward":   [8000]  -> a victim->mgmt->box raw-TCP passthrough + a victim->mgmt SG rule
                                    on these ports (server-mediated EDR clients beacon in).

        The harness reads this at defender arm and calls `request-ingress` with exactly these ports,
        so the box's exposed surface matches precisely what the defender uses. A defender that needs
        nothing returns {} (default) and opens ZERO box ports. Config-aware: e.g. a diagnostic-only
        canary that runs no telemetry checks opens nothing."""
        return {}

    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        mgmt_ip: Optional[str] = None,
    ) -> None:
        """One-time setup this defender needs before it can run (e.g. ensuring shared
        infrastructure like Elasticsearch is up, installing Falco on the experiment's
        hosts). Runs once, before build_config()/run() - default no-op. Mirrors
        AttackerPlugin.setup(); unlike that one there's no per-defender resource (a C2
        container) to tear down on failure, so this has no transactional cleanup -
        raising here just fails the defender start (see run_defender()'s caller).

        `mgmt_ip` is this experiment's own bastion floating IP (from MHBench
        provisioning) - NOT the same as cfg.host_ip (the harness's own fixed
        address, used for Elasticsearch). Any AnsibleRunner use needs THIS one to
        SSH-ProxyCommand into the experiment's internal hosts at all."""

    async def teardown(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
    ) -> None:
        """Best-effort cleanup of harness-side resources this defender created that the
        environment's own teardown doesn't already handle. Runs before the environment
        teardown. Default no-op; the caller (main.py) already wraps this in try/except,
        same best-effort treatment as log collection - a defender teardown failure must
        not block reclaiming the environment's VMs.

        NOTE: stray VMs a defender stood up outside the topology (decoys) are NOT the
        defender's problem to reap - deleting a VM is backend-specific, and defenders are
        backend-agnostic. The ENVIRONMENT sweeps those on its own networks as the first
        step of its teardown (see MHBenchEnvironment._teardown_decoys)."""

    # ------------------------------------------------------------------
    # Readiness handshake
    #
    # A defender's strategy does all of its placement work in initialize()
    # (decoys, fake data, honey credentials) and only then enters the loop that
    # reacts to telemetry. run() below just SPAWNS that process - it returns as
    # soon as the subprocess exists, long before arming is done. Starting the
    # attacker at that point meant the engagement could be over before the
    # defense existed: measured on a ReactiveLayered run, initialize() took
    # 3m45s while the attacker finished its whole chain in 1m38s, so the
    # reactive poll loop never executed a single iteration. These let the
    # harness block until the runner says it is actually armed.
    # ------------------------------------------------------------------
    @staticmethod
    def ready_marker_path(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_ready"

    @classmethod
    def clear_ready_marker(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """Remove a stale marker before starting a defender. Re-running an
        experiment with overwrite=true reuses the same output dir, so a marker
        left by the previous run would otherwise make the gate pass instantly."""
        cls.ready_marker_path(experiment_name, cfg).unlink(missing_ok=True)

    @classmethod
    async def wait_until_ready(
        cls,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        process: asyncio.subprocess.Process,
        log=None,
    ) -> float:
        """Block until the defender's runner reports its strategy is armed.

        Returns seconds spent arming. Raises if the defender process dies first
        (a defender that crashed during initialize() must fail the experiment,
        not quietly hand an undefended environment to the attacker) or if
        arming exceeds cfg.defender_ready_timeout_seconds."""
        marker = cls.ready_marker_path(experiment_name, cfg)
        deadline = asyncio.get_event_loop().time() + cfg.defender_ready_timeout_seconds
        started = asyncio.get_event_loop().time()
        while True:
            if marker.exists():
                waited = asyncio.get_event_loop().time() - started
                if log:
                    log(experiment_name, f"Defender armed after {waited:.1f}s")
                return waited
            if process.returncode is not None:
                raise RuntimeError(
                    f"Defender exited (code {process.returncode}) while arming - "
                    f"see {marker.parent / 'defender.log'}"
                )
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError(
                    f"Defender did not finish arming within "
                    f"{cfg.defender_ready_timeout_seconds}s - see {marker.parent / 'defender.log'}"
                )
            await asyncio.sleep(2)

    # ------------------------------------------------------------------
    # Per-experiment Elasticsearch on the defender box.
    #
    # The environment provisions a bare, isolated box (defender_subnet) and ships sensor telemetry to it
    # via its relay (victim -> relay(mgmt:9200) -> box:9200) under the plain "falco"/"sysflow" indices.
    # A defender that consumes telemetry stands up ES on that box (bare box, no docker/java -> the ES
    # tarball bundles a JDK) and opens an ssh -L tunnel so its detection loop reads the box's own ES at
    # localhost:<port>. Each run gets its OWN ES — no shared, persistent harness ES — which fixes
    # cross-experiment contamination and shard-cap arming failures. Shared by every telemetry-consuming
    # defender (llm_soc / deception / prompt_injection), so it lives on the base.
    # ------------------------------------------------------------------
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

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict: ...

    @abstractmethod
    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process: ...

    @staticmethod
    async def _run_deception_script(
        script_path: Path,
        config_path: Path,
        cfg: ExperimentManagerConfig,
        log_path: Path,
    ) -> asyncio.subprocess.Process:
        """Spawn the plugin's runner.py in deception_dir's own venv, with deception_dir on PYTHONPATH so
        its packages are importable. Shared by every DefenderPlugin subclass backed by that repo
        (deception/prompt_injection) for their run() (the long-running defender loop). Does not wait for
        exit - run() hands the live process back to the harness."""
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        python = str(cfg.get_deception_python())
        pythonpath_parts = [str(cfg.deception_dir)]
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        pythonpath = os.pathsep.join(pythonpath_parts)
        return await asyncio.create_subprocess_exec(
            python,
            str(script_path),
            str(config_path),
            cwd=str(cfg.deception_dir),
            env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
