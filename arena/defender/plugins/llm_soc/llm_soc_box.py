"""Box-RESIDENT variant of the LLM-SOC defender.

Where LLMSOCDefenderPlugin (executes_from_box) runs Perry's detection loop on the HARNESS host and reaches
the box ES over an ssh -L tunnel (+ a thin box agent for host actions), this plugin runs the WHOLE Perry
engine ON the defender box:

  * The arena ships the Perry repo (+ its .env) to the box and provisions a uv standalone CPython-3.12 venv
    there (the box itself is py3.8), installs Perry's requirements, and runs the SAME llm_soc runner under it
    (base _launch_on_box / box_ships_engine). cwd + PYTHONPATH = the shipped engine.
  * The engine reads the per-experiment Elasticsearch at the box's OWN loopback (127.0.0.1:9200) — no harness
    ssh -L tunnel — and calls its LLM directly (the box has outbound internet; live-verified).
  * Its one cloud action, RestoreServer, is an INFRA action routed back to the ENVIRONMENT over the
    harness-initiated ssh -R reverse tunnel (env_action_url + per-experiment token the base bakes in), so the
    box still holds NO cloud credential.

Pure FalcoLLM / FalcoLLMC2Block only: these deploy no decoys and need no box agent (FalcoLLM restores via the
env; C2Block's BlockIP is a host action that would need the agent — gate that later). Kept a SEPARATE plugin
(not a flag on llm_soc) so the live-validated harness-run llm_soc path is untouched; per the relocation plan
the box launch is a cohesive unit lifted into each box plugin later.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
from pathlib import Path
from typing import ClassVar, Literal, Optional

from ....config import ExperimentManagerConfig
from ....ui_schema import PluginUISchema
from .llm_soc import LLMSOCDefenderPlugin, PreparedLLMSOC, _LLM_MODEL_SUGGESTIONS


class LLMSOCBoxDefenderPlugin(LLMSOCDefenderPlugin, config_type="llm_soc_box"):
    """LLM-SOC defender whose detection engine runs ON the defender box (see module docstring)."""

    type: Literal["llm_soc_box"]

    # runs_on_box: the base launcher (_launch_on_box) ships + runs the engine on the box, threading the scoped
    # creds at launch and routing the env-action channel over the token'd ssh -R tunnel. executes_from_box stays
    # True (inherited) so the arena arms that tunnel + env TCP server. box_python selects a uv CPython-3.12 venv
    # (the box is py3.8); box_ships_engine ships the Perry repo, not just the stdlib runner.
    runs_on_box: ClassVar[bool] = True
    box_python: ClassVar[Optional[str]] = "3.12"
    box_ships_engine: ClassVar[bool] = True

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
        # teardown. Nothing to reap here.
        return None
