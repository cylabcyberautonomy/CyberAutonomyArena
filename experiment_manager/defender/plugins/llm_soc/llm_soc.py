from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Literal, Optional

from pydantic import field_validator

from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....environment import DeployedEnvironment
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin

# Model names Perry's own LangChainRegistry (defender/agents/langchain_registry.py)
# knows how to build — a separate, simpler registry from Incalmo's, used only by
# this defender-side LLM agent. The fixed names below (claude-3.7-sonnet, gpt-4o,
# ...) call the direct provider SDKs directly and need ANTHROPIC_API_KEY /
# OPENAI_API_KEY / GOOGLE_API_KEY set - none of which are funded in this
# account. "litellm/<model>" and "openrouter/<model-slug>" route through the
# same working CMU LiteLLM gateway / OpenRouter credentials Incalmo already
# uses (LITELLM_API_KEY+LITELLM_BASE_URL / OPENROUTER_API_KEY in Deception's
# own .env) - prefer those unless a direct-provider key gets added later.
_LLM_MODEL_SUGGESTIONS = [
    "litellm/us.anthropic.claude-sonnet-5",
    "litellm/us.anthropic.claude-haiku-4-5-20251001",
    "litellm/gpt-5",
    "litellm/gemini/gemini-2.5-pro",
    "openrouter/anthropic/claude-sonnet-5",
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


class LLMSOCDefenderPlugin(DefenderPlugin, config_type="llm_soc"):
    """Wraps Perry's LLM-SOC-analyst strategies (defender/strategy/llm/*.py). On a
    Falco-flagged suspicious host, an LLM agent (SysFlowAgent) investigates by
    iteratively querying that host's SysFlow telemetry in Elasticsearch, then
    reports whether it believes the host is compromised and, if so, the attacker's
    C2 IP.

    - FalcoLLM: restores the host from a clean snapshot once the LLM confirms malware.
    - FalcoLLMC2Block: instead blocks the C2 IP the LLM identifies, leaving the host up.
    """

    type: Literal["llm_soc"]
    strategy: str  # "FalcoLLM" or "FalcoLLMC2Block"
    llm_model: str = "litellm/us.anthropic.claude-sonnet-5"

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
                    "default": "litellm/us.anthropic.claude-sonnet-5",
                },
            ],
        }

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict:
        return {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "llm_model": self.llm_model,
            "topology_spec": environment.topology_spec if environment else None,
        }

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        # Perry ("Deception") is one shared repo/venv backing all of its defender
        # plugins — reuse the same deception_dir/deception_python config knobs.
        python = str(cfg.get_deception_python())
        pythonpath_parts = [str(cfg.deception_dir)]
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        pythonpath = os.pathsep.join(pythonpath_parts)
        return await asyncio.create_subprocess_exec(
            python,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            cwd=str(cfg.deception_dir),
            env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
