from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Literal, Optional

from pydantic import field_validator

from .c2c import start_c2c_server, stop_c2c_server, wait_for_agent, wait_for_c2c_ready
from . import foothold
from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ...env_spec import AttackerEnvSpec
from ....ui_schema import PluginUISchema
from ..base import AttackerPlugin


def _foothold_access(experiment):
    """The HARNESS-ONLY FootholdAccess list the arena attached (how to reach the footholds to prep
    them). Never the adversary-safe AttackerEnvSpec — prep needs keys + routing."""
    access = getattr(experiment, "_attacker_access", None)
    if not access:
        raise RuntimeError("no FootholdAccess on the experiment — the arena must attach it before setup")
    return access

_LLM_GROUPS = [
    # LiteLLM deployments routed through the CMU AI gateway (single LITELLM_API_KEY).
    # These are the ones to use here — the direct groups below need per-vendor keys.
    {"group_label": "LiteLLM (CMU gateway)", "options": [
        "gpt-5-mini-litellm", "gpt-5-nano-litellm", "gpt-5.4-mini-litellm", "gpt-4.1-mini-litellm",
        "gpt-5.4-litellm", "gpt-5.5-litellm", "gpt-5.6-sol-litellm",
        "claude-sonnet-4-6-litellm", "claude-haiku-4-5-litellm", "claude-sonnet-5-litellm",
        "claude-opus-4-6-litellm", "claude-opus-4-7-litellm", "claude-opus-4-8-litellm",
        "gemini-2.5-pro-litellm", "gemini-3.1-pro-litellm", "gemini-3.5-flash-litellm",
    ]},
    {"group_label": "Anthropic (direct — needs ANTHROPIC_API_KEY)", "options": [
        "claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-6",
        "claude-4.5-sonnet", "claude-3.7-sonnet", "claude-3.5-sonnet", "claude-3.5-haiku",
    ]},
    {"group_label": "OpenAI (direct — needs OPENAI_API_KEY)", "options": [
        "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
        "gpt-4o", "gpt-4o-mini",
        "o4-mini", "o3-mini", "o3",
        "gpt-5", "gpt-5-mini",
    ]},
    {"group_label": "Google (direct — needs GOOGLE_API_KEY)", "options": [
        "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash",
    ]},
    {"group_label": "DeepSeek (direct — needs DEEPSEEK_API_KEY)", "options": ["deepseek-v3", "deepseek-r1"]},
    {"group_label": "OpenRouter — needs OPENROUTER_API_KEY", "options": [
        "kimi-k3", "glm-5.2", "kimi-k2-base", "qwen3-235b-non-thinking", "glm-4.5",
        "qwen3.8-max", "qwen3-8",
    ]},
]

# The abstraction levels whose actions are LLMAgentAction subclasses (under
# incalmo/core/actions/HighLevel/llm_agents/).  Only these drive an on-host LLM
# sub-agent through LLMAgentInterface, which is the sole consumer of
# execution_llm.  Every other level (incalmo high-level, shell, low_level_actions,
# no_services) translates actions deterministically and ignores execution_llm.
_AGENT_ABSTRACTIONS = [
    "agent_scan", "agent_lateral_move", "agent_privilege_escalation",
    "agent_exfiltrate_data", "agent_find_information", "agent_all",
]

_ABSTRACTION_LEVELS = [
    "incalmo", "shell", "low_level_actions", "no_services",
    *_AGENT_ABSTRACTIONS,
]

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


def _preflight_incalmo_host(cfg: ExperimentManagerConfig) -> None:
    """Fail fast (before any C2 is launched) if the Incalmo host-side prerequisites for
    running the attacker are missing. These live in `incalmo_dir` — a separate repo from the
    harness — and are gitignored there, so a fresh Incalmo checkout won't have them and the
    failure would otherwise surface late and cryptically (a dangling-symlink ENOENT on the
    interpreter, or a FileNotFoundError deep inside strategy init)."""
    # 1. The attacker process runs under this interpreter (see run()). A fresh Incalmo checkout
    #    has no .venv; Path.exists() also returns False for a dangling symlink, so this equally
    #    catches a .venv left pointing at an interpreter that isn't on this host (e.g. one written
    #    by the C2 container before venv isolation).
    py = cfg.get_incalmo_python()
    if not py.exists():
        raise RuntimeError(
            f"Incalmo attacker interpreter not found: {py}\n"
            f"Build the Incalmo host virtualenv before running an Incalmo attacker:\n"
            f"    cd {cfg.incalmo_dir} && uv sync"
        )
    # 2. Incalmo's ConfigService reads ./config/config.json (relative to incalmo_dir, the attacker's
    #    cwd). Its c2c_server is overridden by the C2C_SERVER env var we pass, but — contrary to a
    #    long-standing assumption that this file "only has to exist and parse" — the low-level
    #    scan_network action ALSO reads blacklist_ips from it (via ConfigService, NOT the per-run
    #    AttackerConfig the strategy gets). The shipped example historically blacklisted
    #    192.168.199.10 and 192.168.200.10, so nmap ran `--exclude 192.168.199.10,192.168.200.10`
    #    and the attacker never discovered any host at .10 — in MHBench's equifax/enterprise
    #    topologies that .10 is the key-holding webserver0, so the attacker could never reach the
    #    database tier (0 files exfiltrated). Seed the file when absent, then FORCE blacklist_ips
    #    empty so a stale/hand-edited config.json can't silently blind the attacker again. Per-run
    #    exclusions, if ever needed, belong in the run's AttackerConfig, not this shared file.
    config_json = cfg.incalmo_dir / "config" / "config.json"
    if not config_json.exists():
        example = cfg.incalmo_dir / "config" / "config_example.json"
        if not example.exists():
            raise RuntimeError(
                f"Incalmo config missing: {config_json} (and no {example} to seed it from).\n"
                f"Create {config_json} with a valid AttackerConfig before running an Incalmo attacker."
            )
        shutil.copyfile(example, config_json)
    try:
        _cfg = json.loads(config_json.read_text())
        # Force blacklist_ips to exclude ONLY Kali's docker bridge (172.17.0.0/16), never any
        # 192.168.x victim IP. Two reasons: (a) the shipped default historically blacklisted
        # 192.168.199.10/200.10, hiding the webserver0 that holds the DB keys -> 0 exfil; we must
        # never reintroduce that. (b) Kali runs the C2 in docker, so its host carries 172.17.0.1;
        # Incalmo derives a 172.17.0.0/24 subnet from it and GraphSearch ping-scans it, flooding the
        # attack graph with ~250 phantom bridge hosts that dilute the (shuffled) attack-path queue.
        # scan_network reads blacklist_ips via ConfigService from THIS file, so excluding the bridge
        # here (nmap --exclude 172.17.0.0/16) keeps the graph to real victims.
        if _cfg.get("blacklist_ips") != ["172.17.0.0/16"]:
            _cfg["blacklist_ips"] = ["172.17.0.0/16"]
            config_json.write_text(json.dumps(_cfg, indent=4))
    except (OSError, ValueError):
        # A malformed config.json will fail loudly when the attacker subprocess loads it;
        # don't mask that here — just skip the blacklist normalization.
        pass


class _IncalmoAttacker(AttackerPlugin):
    """Shared C2C lifecycle for all Incalmo-based attackers."""

    requires_docker: ClassVar[bool] = True  # C2 runs as a local Docker container (incalmo/c2c)
    # Opt-in (OpenStack only): run the Incalmo C2 on the in-environment Kali VM instead of a beluga
    # Docker container, so victims beacon to Kali's in-tenant IP (a defender can BlockIP the whole C2
    # IP without hitting shared beluga services). Incalmo-specific, so it lives here on the attacker
    # config — not a harness-global flag. Default False = beluga-docker C2.
    c2_on_kali: bool = False

    async def setup(self, experiment, cfg: ExperimentManagerConfig, mgmt_ip):
        # Validate host-side prerequisites before launching any C2, so a missing venv/config
        # aborts cleanly with a precise fix instead of failing partway through attacker start.
        _preflight_incalmo_host(cfg)
        return await super().setup(experiment, cfg, mgmt_ip)

    async def prepare_foothold(self, experiment, cfg: ExperimentManagerConfig, mgmt_ip, remote_url):
        # The attacker preps its OWN box(es): land the sandcat C2 agent over the harness-only
        # FootholdAccess (key + routing) — no MHBench cli, no environment.deployer.
        await foothold.land_sandcat(_foothold_access(experiment), remote_url, cfg, experiment.experiment_name)

    async def launch_c2c(
        self, experiment_name: str, cfg: ExperimentManagerConfig, mgmt_ip: Optional[str] = None,
        kali_ip: Optional[str] = None,
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        return await start_c2c_server(experiment_name, cfg, mgmt_ip, kali_ip, c2_on_kali=self.c2_on_kali)

    async def wait_c2c_ready(self, local_url: str, experiment_name: str) -> None:
        await wait_for_c2c_ready(local_url, experiment_name)

    async def wait_c2c_agent(self, local_url: str, experiment_name: str) -> None:
        await wait_for_agent(local_url, experiment_name)

    async def stop_c2c(self, container_id: str) -> None:
        await stop_c2c_server(container_id)


# Hardcoded strategies that drive Metasploit directly (via MsfRpcCommand) need
# msfrpcd + pymetasploit3 on the Kali host, exactly like the LLM attacker. Most
# state-machine strategies never touch msf (LateralMoveToHost's msf path is
# llm_interface-gated, which they don't set), so this install is opt-in per
# strategy to avoid paying metasploit-framework's large download for runs that
# never use it.
_MSF_STRATEGIES = {"MsfBindTestStrategy"}


class IncalmoStrategyAttacker(_IncalmoAttacker, config_type="incalmo_strategy"):
    type: Literal["incalmo_strategy"]
    strategy: str  # e.g. "GraphSearch", "Darkside", "EquifaxStrategy"
    script_path: Optional[str] = None  # action_script.json path, required by OptimalReplayStrategy

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value):
        if isinstance(value, list):
            return value[0] if value else "GraphSearch"
        return value

    async def prepare_foothold(self, experiment, cfg: ExperimentManagerConfig, mgmt_ip, remote_url):
        await super().prepare_foothold(experiment, cfg, mgmt_ip, remote_url)
        # Only install msf for strategies that actually dispatch Metasploit ops.
        if self.strategy in _MSF_STRATEGIES:
            await foothold.install_metasploit(_foothold_access(experiment), cfg, experiment.experiment_name)

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

    def build_config(self, experiment_name: str, env_spec: AttackerEnvSpec, c2c_url: str) -> dict:
        strategy = {"name": self.strategy}
        if self.script_path:
            strategy["script_path"] = self.script_path
        return {
            "name": experiment_name,
            "strategy": strategy,
            "environment": env_spec.objective,
            "c2c_server": c2c_url,
            "blacklist_ips": ["172.17.0.0/16"],
        }

    async def run(self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig, c2c_url: str, agent_c2c_url: Optional[str] = None) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(cfg.get_incalmo_python()), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={
                **os.environ,
                "C2C_SERVER": c2c_url,
                # Victim-reachable C2 URL for target-side agent downloads (ExploitStruts etc.).
                # ConfigService reads this from C2C_SERVER_AGENTS; without it the low-level actions
                # fall back to C2C_SERVER, which under c2_on_kali is the 127.0.0.1 tunnel a victim
                # can't reach. Defaults to c2c_url so non-kali backends are unchanged.
                "C2C_SERVER_AGENTS": agent_c2c_url or c2c_url,
                "INCALMO_OUTPUT_DIR": str(output_root(experiment_name, cfg) / experiment_name / "attacker"),
                "PYTHONPATH": str(cfg.incalmo_dir / ".venv" / "lib" / "python3.13" / "site-packages"),
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
            # Own session/process group so a wedged attacker can be SIGKILLed as a whole
            # group (children: ssh, msfrpc, the langchain worker) without the harness having
            # to be in that group — see _force_kill_attacker in main.py.
            start_new_session=True,
        )


class IncalmoLLMAttacker(_IncalmoAttacker, config_type="incalmo_llm"):
    type: Literal["incalmo_llm"]
    planning_llm: str
    # Only the agent_* abstractions consume execution_llm (see _AGENT_ABSTRACTIONS
    # and the show_when gate below).  Optional so the dashboard can omit it for
    # non-agent abstractions; build_config falls back to planning_llm.
    execution_llm: str = ""
    abstraction: str = "incalmo"

    async def prepare_foothold(self, experiment, cfg: ExperimentManagerConfig, mgmt_ip, remote_url):
        await super().prepare_foothold(experiment, cfg, mgmt_ip, remote_url)
        # Only this (LLM-driven) attacker can ever reach LateralMoveToHost's Metasploit path (gated
        # on context.llm_interface being set) - IncalmoStrategyAttacker never does. msfrpcd has to
        # run on the Kali box itself (it binds 127.0.0.1, and the box has no floating IP), which is
        # exactly why the attacker installs it on its own foothold here.
        await foothold.install_metasploit(_foothold_access(experiment), cfg, experiment.experiment_name)

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "incalmo_llm",
            "label": "Incalmo LLM",
            "cartesian_product": True,
            "fields": [
                {
                    "field_type": "grouped_checkboxes",
                    "label": "Planning LLM",
                    "key": "planning_llm",
                    "groups": _LLM_GROUPS,
                },
                {
                    "field_type": "grouped_checkboxes",
                    "label": "Execution LLM",
                    "key": "execution_llm",
                    "groups": _LLM_GROUPS,
                    # Sub-agent LLM: relevant only for the agent_* abstractions.
                    "show_when": {"abstraction": _AGENT_ABSTRACTIONS},
                },
                {
                    "field_type": "flat_checkboxes",
                    "label": "Abstraction",
                    "key": "abstraction",
                    "options": _ABSTRACTION_LEVELS,
                    "short_names": {
                        "incalmo": "incalmo",
                        "shell": "shell",
                        "low_level_actions": "lowlevel",
                        "no_services": "no_svcs",
                        "agent_scan": "agent_scan",
                        "agent_lateral_move": "agent_latmv",
                        "agent_privilege_escalation": "agent_privesc",
                        "agent_exfiltrate_data": "agent_exfil",
                        "agent_find_information": "agent_find",
                        "agent_all": "agent_all",
                    },
                },
            ],
        }

    def build_config(self, experiment_name: str, env_spec: AttackerEnvSpec, c2c_url: str) -> dict:
        return {
            "name": experiment_name,
            "strategy": {
                "planning_llm": self.planning_llm,
                # execution_llm only matters for agent_* abstractions; for the
                # rest it is ignored by Incalmo, so default it to planning_llm.
                "execution_llm": self.execution_llm or self.planning_llm,
                "abstraction": self.abstraction,
            },
            "environment": env_spec.objective,
            "c2c_server": c2c_url,
            "blacklist_ips": ["172.17.0.0/16"],
        }

    async def run(self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig, c2c_url: str, agent_c2c_url: Optional[str] = None) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(cfg.get_incalmo_python()), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={
                **os.environ,
                "C2C_SERVER": c2c_url,
                # Victim-reachable C2 URL for target-side agent downloads (ExploitStruts etc.).
                # ConfigService reads this from C2C_SERVER_AGENTS; without it the low-level actions
                # fall back to C2C_SERVER, which under c2_on_kali is the 127.0.0.1 tunnel a victim
                # can't reach. Defaults to c2c_url so non-kali backends are unchanged.
                "C2C_SERVER_AGENTS": agent_c2c_url or c2c_url,
                "INCALMO_OUTPUT_DIR": str(output_root(experiment_name, cfg) / experiment_name / "attacker"),
                "PYTHONPATH": str(cfg.incalmo_dir / ".venv" / "lib" / "python3.13" / "site-packages"),
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
            # Own session/process group so a wedged attacker can be SIGKILLed as a whole
            # group (children: ssh, msfrpc, the langchain worker) without the harness having
            # to be in that group — see _force_kill_attacker in main.py.
            start_new_session=True,
        )
