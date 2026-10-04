from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Optional

from pydantic import field_validator

from .c2 import (start_c2c_server, stop_c2c_server, wait_for_agent, wait_for_c2c_ready,
                 sweep_stale_tunnels)
from . import foothold
from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ...env_spec import AttackerEnvSpec
from ....ui_schema import PluginUISchema
from ..base import AttackerPlugin, PreparedAttacker

# Incalmo C2 attacker driven by a FIXED strategy (GraphSearch, Darkside, …). Self-contained: it carries
# its own copy of the Incalmo C2 lifecycle + helpers (c2.py / foothold.py / aux/), mirroring the sibling
# `incalmo_llm` plugin — one plugin per folder, each duplicating the shared C2 machinery (like the three
# Defense/Perry defenders each copy box_es_install.sh). Both point at the same Incalmo repo via their own
# code-path config fields (incalmo_strategy_dir vs incalmo_llm_dir).


def _require_access(access):
    """The HARNESS-ONLY SetupAccess list the arena passes to run_setup (how to reach the footholds to
    prep them). Never the adversary-safe AttackerEnvSpec — prep needs keys + routing."""
    if not access:
        raise RuntimeError("no SetupAccess passed to the attacker — the arena must pass it to run_setup()")
    return access


# Bypasses ConfigService (which hardcodes ./config/config.json) by loading
# config from a path passed as argv[1].
_RUNNER = """\
import asyncio, json, sys
from pathlib import Path
from config.attacker_config import AttackerConfig
from incalmo.c2server.state_store import StateStore
from incalmo.incalmo_runner import run_incalmo_strategy

config = AttackerConfig(**json.loads(Path(sys.argv[1]).read_text()))
StateStore.initialize()
asyncio.run(run_incalmo_strategy(config, task_id=sys.argv[2]))
"""


def _preflight_incalmo_host(incalmo_dir: Path, incalmo_python: Path) -> None:
    """Fail fast (before any C2 is launched) if the Incalmo host-side prerequisites for
    running the attacker are missing. These live in `incalmo_dir` — a separate repo from the
    harness — and are gitignored there, so a fresh Incalmo checkout won't have them and the
    failure would otherwise surface late and cryptically (a dangling-symlink ENOENT on the
    interpreter, or a FileNotFoundError deep inside strategy init). `incalmo_dir`/`incalmo_python`
    are the per-plugin code path + interpreter the caller resolved from cfg."""
    # 1. The attacker process runs under this interpreter (see run()). A fresh Incalmo checkout
    #    has no .venv; Path.exists() also returns False for a dangling symlink, so this equally
    #    catches a .venv left pointing at an interpreter that isn't on this host (e.g. one written
    #    by the C2 container before venv isolation).
    py = incalmo_python
    if not py.exists():
        raise RuntimeError(
            f"Incalmo attacker interpreter not found: {py}\n"
            f"Build the Incalmo host virtualenv before running an Incalmo attacker:\n"
            f"    cd {incalmo_dir} && uv sync"
        )
    # 2. Incalmo's ConfigService reads ./config/config.json (relative to incalmo_dir, the attacker's
    #    cwd). Its c2c_server is overridden by the C2C_SERVER env var we pass, but the low-level
    #    scan_network action ALSO reads blacklist_ips from this file (via ConfigService, NOT the
    #    per-run AttackerConfig the strategy gets). A blacklist entry becomes an `nmap --exclude`,
    #    so a stale or hand-edited config.json that lists a victim subnet silently hides those hosts
    #    from discovery — the attacker then never reaches them. Seed the file when absent, then
    #    normalize blacklist_ips below so such a config can't blind the attacker. Per-run exclusions,
    #    if ever needed, belong in the run's AttackerConfig, not this shared file.
    config_json = incalmo_dir / "config" / "config.json"
    if not config_json.exists():
        example = incalmo_dir / "config" / "config_example.json"
        if not example.exists():
            raise RuntimeError(
                f"Incalmo config missing: {config_json} (and no {example} to seed it from).\n"
                f"Create {config_json} with a valid AttackerConfig before running an Incalmo attacker."
            )
        shutil.copyfile(example, config_json)
    try:
        _cfg = json.loads(config_json.read_text())
        # Normalize blacklist_ips to exclude ONLY the C2 host's Docker bridge (172.17.0.0/16), never
        # a victim subnet. Two reasons: (a) blacklisting a victim subnet hides those hosts from the
        # attacker's scan (see above), so we must never let one persist here. (b) The C2 runs in
        # Docker, so its host carries 172.17.0.1; Incalmo derives a 172.17.0.0/24 subnet from it and
        # GraphSearch ping-scans it, flooding the attack graph with phantom bridge hosts that dilute
        # the attack-path queue. scan_network reads blacklist_ips via ConfigService from THIS file,
        # so excluding the bridge here (nmap --exclude 172.17.0.0/16) keeps the graph to real victims.
        if _cfg.get("blacklist_ips") != ["172.17.0.0/16"]:
            _cfg["blacklist_ips"] = ["172.17.0.0/16"]
            config_json.write_text(json.dumps(_cfg, indent=4))
    except (OSError, ValueError):
        # A malformed config.json will fail loudly when the attacker subprocess loads it;
        # don't mask that here — just skip the blacklist normalization.
        pass


@dataclass
class IncalmoPreparedC2(PreparedAttacker):
    """Incalmo's setup() output: the C2's URLs, carried on the opaque baton for Incalmo's OWN
    build_config()/run() to read. The arena never inspects these — it just passes the baton through."""
    remote_url: Optional[str] = None   # the foothold's in-env address victims / sandcat agents beacon to
    local_url: Optional[str] = None    # 127.0.0.1 ssh -L tunnel the attacker LLM reaches the C2 through


# Hardcoded strategies that drive Metasploit directly (via MsfRpcCommand) need
# msfrpcd + pymetasploit3 on the foothold, exactly like the LLM attacker. Most
# state-machine strategies never touch msf (LateralMoveToHost's msf path is
# llm_interface-gated, which they don't set), so this install is opt-in per
# strategy to avoid paying metasploit-framework's large download for runs that
# never use it.
_MSF_STRATEGIES = {"MsfBindTestStrategy"}


class IncalmoStrategyAttacker(AttackerPlugin, config_type="incalmo_strategy"):
    type: Literal["incalmo_strategy"]

    # The C2 image is built with Docker on the harness host before it is shipped to the foothold.
    requires_docker: ClassVar[bool] = True
    # Per-plugin code path (points at the Incalmo repo). The sibling incalmo_llm plugin names its own
    # (incalmo_llm_dir) — redundant by design so no field silently backs both.
    code_dir_field: ClassVar[str] = "incalmo_strategy_dir"
    code_python_field: ClassVar[str] = "incalmo_strategy_python"

    REQUIRED_CONFIG_KEYS = frozenset(
        {"name", "strategy", "environment", "c2c_server", "agent_c2c_server", "blacklist_ips"})
    strategy: str  # e.g. "GraphSearch", "Darkside", "EquifaxStrategy"
    script_path: Optional[str] = None  # action_script.json path, required by OptimalReplayStrategy

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value):
        if isinstance(value, list):
            return value[0] if value else "GraphSearch"
        return value

    # ---- Incalmo C2 lifecycle (self-contained; a copy also lives in plugins/incalmo_llm/) -------------
    def _code_dir(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_dir(self.code_dir_field)

    def _code_python(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_python(self.code_dir_field, self.code_python_field)

    @classmethod
    def example_prepared(cls) -> PreparedAttacker:
        """build_config() reads the C2 URLs off its own baton — hand it a filled-in one for offline tests."""
        return IncalmoPreparedC2(local_url="http://127.0.0.1:8888", remote_url="http://foothold:8888")

    @classmethod
    def sweep_stale_state(cls, cfg: ExperimentManagerConfig) -> None:
        # Reap orphaned foothold-C2 ssh -L tunnels left by a crashed prior manager (no-op if none).
        sweep_stale_tunnels()

    async def setup(self, experiment, cfg: ExperimentManagerConfig, bastion_ip, access=None) -> PreparedAttacker:
        # Validate host-side prerequisites before launching any C2, so a missing venv/config
        # aborts cleanly with a precise fix instead of failing partway through attacker start.
        _preflight_incalmo_host(self._code_dir(cfg), self._code_python(cfg))
        # Bring up the C2 on the attacker's foothold, prep the foothold, and block until an agent
        # beacons in. Transactional: tear down a partial C2 on failure.
        foothold_access = self.primary_access(access) if access else None
        if foothold_access is None:
            raise RuntimeError("the Incalmo C2 runs on the attacker foothold, but setup() got no SetupAccess")
        _sentinel, remote_url, local_url = await self.launch_c2c(
            experiment.experiment_name, cfg, bastion_ip, foothold_access=foothold_access)
        try:
            if local_url:
                await self.wait_c2c_ready(local_url, experiment.experiment_name)
            await self.prepare_foothold(experiment, cfg, bastion_ip, remote_url, access)
            if local_url:
                await self.wait_c2c_agent(local_url, experiment.experiment_name)
        except Exception:
            await self.teardown(experiment.experiment_name, cfg)  # tear down a partial C2 (keyed by name)
            raise
        return IncalmoPreparedC2(remote_url=remote_url, local_url=local_url)

    async def prepare_foothold(self, experiment, cfg: ExperimentManagerConfig, bastion_ip, remote_url, access=None):
        # The attacker preps its OWN box(es): land the sandcat C2 agent over the harness-only
        # SetupAccess (key + routing) the arena passed in — no MHBench cli, no environment.deployer.
        await foothold.land_sandcat(_require_access(access), remote_url, cfg, experiment.experiment_name)
        # Only install msf for strategies that actually dispatch Metasploit ops (opt-in per strategy
        # to avoid metasploit-framework's large download for runs that never use it).
        if self.strategy in _MSF_STRATEGIES:
            await foothold.install_metasploit(_require_access(access), cfg, experiment.experiment_name)

    async def launch_c2c(
        self, experiment_name: str, cfg: ExperimentManagerConfig, bastion_ip: Optional[str] = None,
        foothold_access=None,
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        return await start_c2c_server(experiment_name, cfg, bastion_ip, foothold_access=foothold_access,
                                      incalmo_dir=self._code_dir(cfg))

    async def wait_c2c_ready(self, local_url: str, experiment_name: str) -> None:
        await wait_for_c2c_ready(local_url, experiment_name)

    async def wait_c2c_agent(self, local_url: str, experiment_name: str) -> None:
        await wait_for_agent(local_url, experiment_name)

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        await stop_c2c_server(experiment_name)

    # ---- strategy-specific config + launch -----------------------------------------------------------
    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "incalmo_strategy",
            "label": "Incalmo Strategy",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Strategy",
                    "key": "strategy",
                    "options": ["GraphSearch", "Darkside", "EquifaxStrategy", "MulvalOptimal", "OptimalReplayStrategy"],
                    "short_names": {
                        "GraphSearch": "graphsrch",
                        "Darkside": "darkside",
                        "EquifaxStrategy": "eq_strategy",
                        "MulvalOptimal": "mulval_opt",
                        "OptimalReplayStrategy": "opt_replay",
                    },
                },
                {
                    "field_type": "text_with_suggestions",
                    "label": "Script path (OptimalReplayStrategy only)",
                    "key": "script_path",
                    "suggestions": [],
                    "default": "",
                },
            ],
        }

    def build_config(self, experiment_name: str, env_spec: AttackerEnvSpec, prepared: PreparedAttacker) -> dict:
        strategy = {"name": self.strategy}
        if self.script_path:
            strategy["script_path"] = self.script_path
        return {
            "name": experiment_name,
            "strategy": strategy,
            "environment": env_spec.objective,
            # C2 URLs come from Incalmo's OWN setup handle: c2c_server = the LLM's tunnel to the C2,
            # agent_c2c_server = the foothold's in-env address victims fetch the implant from.
            "c2c_server": prepared.local_url,
            "agent_c2c_server": prepared.remote_url,
            "blacklist_ips": ["172.17.0.0/16"],
        }

    async def run(self, prepared: PreparedAttacker, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(self._code_python(cfg)), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(self._code_dir(cfg)),
            env={
                **os.environ,
                "C2C_SERVER": prepared.local_url,
                # Victim-reachable C2 URL for target-side agent downloads (ExploitStruts etc.).
                # ConfigService reads this from C2C_SERVER_AGENTS; without it the low-level actions
                # fall back to C2C_SERVER, which is the 127.0.0.1 ssh -L tunnel a victim can't reach.
                # So agents get the foothold's in-env address; the LLM's own C2 API uses the tunnel.
                "C2C_SERVER_AGENTS": prepared.remote_url or prepared.local_url,
                "INCALMO_OUTPUT_DIR": str(output_root(experiment_name, cfg) / experiment_name / "attacker"),
                "PYTHONPATH": str(self._code_dir(cfg) / ".venv" / "lib" / "python3.13" / "site-packages"),
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
            # Own session/process group so a wedged attacker can be SIGKILLed as a whole
            # group (children: ssh, msfrpc, the langchain worker) without the harness having
            # to be in that group — see _force_kill_attacker in main.py.
            start_new_session=True,
        )
