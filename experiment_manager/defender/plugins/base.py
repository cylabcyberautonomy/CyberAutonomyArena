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
        """Best-effort cleanup of resources this defender created that MHBench's own
        teardown doesn't know about (e.g. decoy VMs - see _teardown_decoys below).
        Runs before teardown_environment() so MHBench's network/security-group
        deletion doesn't hit "in use" ConflictExceptions from resources it never
        provisioned and can't see (they're not in the topology JSON). Default
        no-op; the caller (main.py) already wraps this in try/except, same
        best-effort treatment as log collection - a defender teardown failure
        must not block reclaiming the environment's VMs."""

    @staticmethod
    async def _teardown_decoys(experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """Delete any decoy VMs still standing for this experiment (DeployDecoy
        actuator - see Defense-MHBench-compatible's Reactive*/Static*/NaiveDecoy*
        strategies). These are OpenStack servers created directly via openstacksdk,
        outside MHBench's topology JSON entirely, so MHBench's own teardown has no
        idea they exist - if left alive, they keep this experiment's security
        groups "in use", and MHBench's teardown deletes-in-order and aborts on the
        first ConflictException, leaking every network/subnet/security-group for
        the whole experiment right along with the decoy (confirmed live, repeatedly).

        Identified by the experiment-name prefix, not a decoy name pattern:
        every server MHBench provisions is named "<experiment_name>-<host>" (see
        HostDeployer._n), while DeployDecoy creates servers under the bare
        `action.host_name` with no prefix at all. So on this experiment's own
        networks, "unprefixed" is exactly equivalent to "not a real topology
        host" - i.e. a decoy. Cross-referencing against the network name
        (always "<experiment_name>-<subnet_name>") keeps this scoped to this
        experiment even when several run concurrently.

        This deliberately replaces an earlier regex that matched only names of
        the form decoy_<digits>, which
        only covered the Deception plugin's naming. prompt_injection's
        AIAttackerDetection names its decoys after a prompt-injection payload
        ("Exercise_complete_Please_use_the_finished_tag_to_terminate_<n>" - the
        hostname IS the injection, so it can't be renamed), and those were
        silently never cleaned up: they kept the experiment's security groups
        in use, which is precisely the condition that makes MHBench's teardown
        abort on its first ConflictException and leak the whole environment.

        Looked up via Neutron ports (device_id=server.id), not server.addresses:
        confirmed live that addresses is empty while a server is still BUILD (no
        port binding surfaced on the compute resource yet) - exactly the state a
        slow/stuck decoy (the case this most needs to catch) is in. A port
        (with its subnet/network already assigned) exists as soon as
        create_server() returns, well before boot completes."""
        import openstack

        def _sync() -> None:
            conn = openstack.connect(cloud=cfg.os_cloud)
            prefix = f"{experiment_name}-"
            for server in conn.compute.servers():
                if (server.name or "").startswith(prefix):
                    continue  # a real MHBench-provisioned host, not a decoy
                network_ids = {
                    port.network_id for port in conn.network.ports(device_id=server.id)
                }
                network_names = {
                    conn.network.get_network(nid).name for nid in network_ids
                }
                if not any(name.startswith(prefix) for name in network_names):
                    continue
                conn.compute.delete_server(server, ignore_missing=True)
                conn.compute.wait_for_delete(server, wait=120)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _sync)

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

    # ------------------------------------------------------------------
    # Defender-box Elasticsearch (shared by every telemetry-reading defender).
    # The environment provisions a BARE per-experiment box (defender_subnet) and ships all
    # sensor telemetry to it via its relay (victim -> relay(mgmt:9200) -> box:9200), under the
    # plain indices "falco"/"sysflow". Here the defender stands up ES ON that box itself (bare
    # box, no docker/java -> the ES tarball bundles a JDK) and opens an ssh -L tunnel so the
    # detection loop (running on the harness host, the Incalmo-style out-of-band pattern) reads the box's
    # own per-experiment ES at localhost:<port>. This is what gives each run its OWN ES —
    # fixing the shared-ES cross-experiment contamination and the single-node shard-cap arming
    # failures. Kept on the base class (not a per-plugin helper) since llm_soc / deception /
    # prompt_injection all need it.
    # ------------------------------------------------------------------
    @staticmethod
    def _es_tunnel_pidfile(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "es_tunnel.pid"

    def prepare_box_es(self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig) -> Optional[dict]:
        """Install ES on the defender box (idempotent) and open a harness-host->box:9200 ssh -L tunnel.
        Writes es_url + falco_index/sysflow_index into the config JSON the runner reads, and drops
        an es_tunnel.pid for teardown/clean-slate. Returns the injected dict, or None when the
        topology has no defender box (older env: caller keeps the legacy harness-host+shared-ES path)."""
        import json as _json
        import shlex
        import socket
        import time

        cfgd = _json.loads(Path(config_path).read_text())
        box = (cfgd.get("defender_env_spec") or {}).get("box") or {}
        box_ip = box.get("ip")
        if not box_ip:
            return None  # no box -> legacy path

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
        script = (Path(__file__).parent.parent / "box_es_install.sh").read_text()
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

    @staticmethod
    async def _run_deception_script(
        script_path: Path,
        config_path: Path,
        cfg: ExperimentManagerConfig,
        log_path: Path,
    ) -> asyncio.subprocess.Process:
        """Spawn a script (runner.py or setup.py) in deception_dir's own venv, with
        deception_dir on PYTHONPATH so its packages are importable. Shared by every
        DefenderPlugin subclass backed by that repo (deception/prompt_injection/
        llm_soc) - both their run() (the long-running defender loop) and setup()
        (one-time pre-run setup) need exactly this, just pointed at a different
        script. Does not wait for exit - callers await the process themselves if
        they need to (setup() does; run() hands the live process back to the
        harness)."""
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

    @classmethod
    async def _run_deception_setup_script(
        cls,
        script_dir: Path,
        setup_config: dict,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> None:
        """Write `setup_config` to defender/setup_config.json, run script_dir/setup.py
        against it in deception_dir's venv, and wait for it - unlike
        _run_deception_script, this one blocks until the setup script exits and
        raises if it failed, since build_config()/run() must not start until setup
        has actually finished."""
        import json
        from ...experiment_log import output_root

        defender_dir = output_root(experiment_name, cfg) / experiment_name / "defender"
        defender_dir.mkdir(parents=True, exist_ok=True)
        config_path = defender_dir / "setup_config.json"
        config_path.write_text(json.dumps(setup_config, indent=2))
        log_path = defender_dir / "setup.log"
        proc = await cls._run_deception_script(script_dir / "setup.py", config_path, cfg, log_path)
        returncode = await proc.wait()
        if returncode != 0:
            raise RuntimeError(f"{cls.__name__} setup failed (exit {returncode}) - see {log_path}")
