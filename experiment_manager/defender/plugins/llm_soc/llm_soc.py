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
# The Sonnet-4.5-vs-5 defender comparison MUST keep both arms on ONE route, or
# provider/backend differences confound the model comparison. OpenRouter is the
# only route that serves BOTH: the CMU LiteLLM gateway
# (ai-gateway.andrew.cmu.edu) exposes claude-sonnet-4, -4-6 and -5 but NO 4.5
# (verified against its /models list, 2026-09-14). So the two canonical arms are
# the OpenRouter slugs below (both confirmed present in OpenRouter's /models).
# Keep them first, and do not pin the 5 arm to litellm/... while the 4.5 arm is
# on openrouter/... .
_LLM_MODEL_SUGGESTIONS = [
    # Canonical same-route comparison pair (OpenRouter):
    "openrouter/anthropic/claude-sonnet-5",
    "openrouter/anthropic/claude-sonnet-4.5",
    "litellm/us.anthropic.claude-sonnet-5",
    "litellm/us.anthropic.claude-haiku-4-5-20251001",
    "litellm/gpt-5",
    "litellm/gemini/gemini-2.5-pro",
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
    # Default to Sonnet-5 on OpenRouter so it shares a route with the 4.5
    # comparison arm (openrouter/anthropic/claude-sonnet-4.5). See
    # _LLM_MODEL_SUGGESTIONS for why litellm can't host the 4.5 arm.
    llm_model: str = "openrouter/anthropic/claude-sonnet-5"

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
                    "default": "openrouter/anthropic/claude-sonnet-5",
                },
            ],
        }

    def box_ingress(self) -> dict[str, list[int]]:
        # FalcoLLM reads the box ES (falco + sysflow) -> needs telemetry routed to box:9200.
        return {"telemetry": [9200]}

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

    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        mgmt_ip: Optional[str] = None,
    ) -> None:
        """Ensure the shared Elasticsearch instance is up before the runner starts.

        This plugin's runner connects to Elasticsearch immediately (its
        TelemetryAnalysis calls indices.exists() in __init__) and installs Falco
        pointed at the same address, so ES has to already be listening. It had no
        setup() at all and so silently depended on some *other* experiment - in
        practice a Deception run - having started the container first; on a fresh
        host the runner just died on connection refused. Reuses the Deception
        plugin's setup.py rather than duplicating it: the script only bootstraps
        the shared ES container (idempotent, safe under concurrent experiments)
        and is not deception-specific.
        """
        await self._run_deception_setup_script(
            Path(__file__).parent.parent / "deception",
            {"deception_dir": str(cfg.deception_dir), "management_ip": cfg.host_ip},
            experiment_name,
            cfg,
        )

    async def teardown(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
    ) -> None:
        # Kill the harness-host->box ES ssh -L tunnel (no-op if this run used the legacy path).
        # Stray decoy VMs, if any, are reaped by the environment's own teardown, not here.
        self._teardown_box_es_tunnel(experiment_name, cfg)

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
        # If the environment provides a defender box, stand up ES on it and tunnel to it, so this
        # run reads its OWN per-experiment ES (fixes shared-ES contamination + shard-cap). Blocking
        # (SSH install + wait), so run it off the event loop. No box -> None -> legacy harness-host+shared-ES.
        await asyncio.get_event_loop().run_in_executor(
            None, self.prepare_box_es, config_path, experiment_name, cfg)
        return await asyncio.create_subprocess_exec(
            python,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            cwd=str(cfg.deception_dir),
            env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    # ------------------------------------------------------------------
    # Per-experiment Elasticsearch on the defender box. The environment provisions a bare box
    # (defender_subnet) and ships sensor telemetry to it via its relay (victim -> relay(mgmt:9200) ->
    # box:9200) under the plain "falco"/"sysflow" indices. FalcoLLM stands up ES on that box (bare box,
    # no docker/java -> the ES tarball bundles a JDK) and opens an ssh -L tunnel so the detection loop
    # reads the box's own ES at localhost:<port> — each run gets its OWN ES, fixing shared-ES
    # cross-experiment contamination + shard-cap arming failures. llm_soc is the only defender that
    # reads ES, so this lives here rather than on the DefenderPlugin base.
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
