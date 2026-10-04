from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Literal, Optional

from pydantic import field_validator

from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin, PreparedDefender

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
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "strategy", "llm_model"})
    code_dir_field = "llm_soc_dir"          # Defense/Perry repo for this defender (per-plugin)
    executes_from_box = True                 # box-only execution: deploy the box agent + arm the env channel
    code_python_field = "llm_soc_python"
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
        env_spec,
        prepared: PreparedDefender,
    ) -> dict:
        built = {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "llm_model": self.llm_model,
            # No topology_spec: this defender builds its Network from the env-provided DefenderEnvSpec
            # (injected as defender_env_spec by run_defender), not from the MHBench topology JSON.
        }
        # Bake the Phase-A baton (box ES tunnel url + indices, box agent endpoint) the runner reads —
        # produced by provision_box() before this call, replacing the old prepare_box_es config patch.
        built.update(self._env_spec_key(env_spec))   # agent-facing host inventory (typed arg)
        built.update(self._baton_keys(prepared))
        return built

    async def provision_box(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
        needs_agent: bool = False,
    ) -> PreparedDefender:
        # PHASE A (runs BEFORE build_config): stand up this run's OWN per-experiment ES on the defender box
        # + the ssh -L tunnel (prepare_box_es), and — when this run armed dynamic topology (needs_agent) —
        # deploy + start the box agent. Both take the env-produced box inventory + access (NOT a written
        # config, which doesn't exist yet) and RETURN their values; build_config() bakes them into the
        # runner config via the baton. llm_soc's strategies (FalcoLLM / FalcoLLMC2Block) arm IN the loop —
        # they deploy no decoys — so there is no Phase-B prepare() here; the base no-op covers it. Blocking
        # SSH work, so off the event loop.
        box_cfg = {
            "defender_env_spec": defender_env_spec.model_dump() if defender_env_spec is not None else {},
            "defender_setup_access": [a.model_dump() for a in (defender_access or [])],
        }
        loop = asyncio.get_event_loop()
        es = await loop.run_in_executor(None, self.prepare_box_es, box_cfg, experiment_name, cfg)
        baton = dict(es)
        if needs_agent:
            box_cfg.update(es)  # the box-agent config reads sysflow_index from prepare_box_es's output
            agent = await loop.run_in_executor(None, self.prepare_box_agent, box_cfg, experiment_name, cfg)
            baton.update(agent)
        return PreparedDefender(**baton)

    # -- box agent deploy (the defender's in-environment effector) ---------------------------------
    # Copied per dynamic-defender plugin (box_agent_install.sh co-located), like prepare_box_es. Ships the
    # Perry runtime to the bare box, starts the agent on box:8900, opens a harness->box ssh -L tunnel (the
    # box is in-env, only reachable via the bastion), and injects box_agent_host/port/token into the config
    # the runner reads so RemoteEnvOrchestrator.from_config can reach it. NOT YET LIVE-VALIDATED.
    def _box_agent_tunnel_pidfile(self, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "box_agent_tunnel.pid"

    def prepare_box_agent(self, src_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        import json as _json
        import secrets
        import shlex
        import socket
        import time

        cfgd = src_cfg
        box = (cfgd.get("defender_env_spec") or {}).get("box") or {}
        box_ip = box.get("ip")
        if not box_ip:
            raise RuntimeError("no defender box in defender_env_spec; box agent requires one")
        access = next((a for a in cfgd.get("defender_setup_access", []) if a.get("host") == box_ip), None)
        if not access or not access.get("ssh_key"):
            raise RuntimeError(f"defender box {box_ip} present but no SetupAccess with an ssh_key")
        key = os.path.expanduser(access["ssh_key"])
        common = shlex.split(access.get("ssh_common_args") or "")
        user = access.get("user", "root")
        port = str(access.get("port", 22))
        ssh_opts = ["-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", "-p", port, *common]
        ssh_base = ["ssh", *ssh_opts]
        target = f"{user}@{box_ip}"
        repo_dir = str(self._code_dir(cfg))

        # 1. ship ONLY the ansible/ YAML tree + the standalone agent (the self-contained agent imports no
        #    Perry Python — which needs py3.10+ — so the box's py3.8 is fine). Via the bastion jump.
        rsync_e = "ssh " + " ".join(shlex.quote(o) for o in ssh_opts)
        subprocess.run(
            # artifacts/ is ansible-runner's OWN output (gitignored UUID job dirs — can grow to GBs over a
            # live checkout's lifetime; no playbook reads it), so never ship it to the box: it has blown the
            # 600s timeout on a bloated checkout. The box needs the YAML + vendored .deb/.zip inputs only.
            ["rsync", "-a", "--delete", "-e", rsync_e, "--exclude", ".git", "--exclude", "__pycache__",
             "--exclude", "artifacts",
             repo_dir.rstrip("/") + "/ansible/", f"{target}:/root/ansible/"],
            check=True, timeout=600)
        agent_src = Path(repo_dir) / "defender" / "box_agent" / "agent.py"
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_agent.py"],
                       input=agent_src.read_text(), text=True, check=True, timeout=60)
        # 2. ship the scoped key the box agent's AnsibleRunner uses to reach victims (box -> victim direct).
        subprocess.run([*ssh_base, target, "cat > /root/scoped_key && chmod 600 /root/scoped_key"],
                       input=Path(key).read_text(), text=True, check=True, timeout=60)
        # 3. write + ship the box-agent config.
        token = secrets.token_urlsafe(24)
        box_cfg = {
            "token": token, "host": "127.0.0.1", "port": 8900,
            "ssh_key_path": "/root/scoped_key", "ansible_dir": "/root/ansible", "log_dir": "/root",
            # A decoy's SysFlow exports to the box's OWN ES, reached from the decoy at the box's in-env
            # address (the box runs ES on :9200 from prepare_box_es). Plain HTTP, no auth (box ES has
            # security disabled). NOTE live-unknown: decoy->box:9200 routing + box ES binding 0.0.0.0.
            "es_address": f"http://{box_ip}:9200",
            "es_index": cfgd.get("sysflow_index", "sysflow"),
        }
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_config.json"],
                       input=_json.dumps(box_cfg), text=True, check=True, timeout=60)
        # 4. ship + run the install/start script (idempotent).
        script = (Path(__file__).parent / "box_agent_install.sh").read_text()
        subprocess.run([*ssh_base, target, "cat > /root/box_agent_install.sh && chmod +x /root/box_agent_install.sh"],
                       input=script, text=True, check=True, timeout=60)
        subprocess.run([*ssh_base, target, "/root/box_agent_install.sh"], check=True, timeout=600)
        # 5. open a harness->box:8900 ssh -L tunnel (box is in-env, reachable only through the bastion).
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            lport = s.getsockname()[1]
        tunnel = subprocess.Popen([*ssh_base, "-N", "-L", f"{lport}:localhost:8900", target],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pidfile = self._box_agent_tunnel_pidfile(experiment_name, cfg)
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(tunnel.pid))
        # 6. wait for the agent's /health through the tunnel.
        import urllib.request
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{lport}/health", timeout=5) as r:
                    if r.status == 200:
                        break
            except Exception:  # noqa: BLE001
                time.sleep(3)
        else:
            raise RuntimeError(f"box agent did not answer /health on {box_ip}:8900 within 120s")
        # 7. inject the reachable host/port/token into the config the runner reads.
        return {"box_agent_host": "127.0.0.1", "box_agent_port": lport, "box_agent_token": token}

    async def teardown(
        self,
        experiment_name: str,
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
        # Perry ("Deception") is one shared repo backing all of its defender plugins, but each names its
        # OWN code path now (per-plugin) — resolve this plugin's repo + interpreter.
        repo_dir = self._code_dir(cfg)
        python = str(self._code_python(cfg))
        pythonpath_parts = [str(repo_dir)]
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        pythonpath = os.pathsep.join(pythonpath_parts)
        # The box ES + tunnel were stood up in prepare(); here we only launch the reactive loop
        # ("run" mode -> runner.py calls defender.start(prepared=True) and polls the box ES).
        return await asyncio.create_subprocess_exec(
            python,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            "run",
            cwd=str(repo_dir),
            env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    # -- per-experiment Elasticsearch on the defender box -----------------------------------------
    # The environment provisions a bare, isolated box (defender_subnet) and ships sensor telemetry to it
    # via its relay (victim -> relay(mgmt:9200) -> box:9200) under plain "falco"/"sysflow" indices. This
    # defender stands up ES on the box (bare box, no docker/java -> the ES tarball bundles a JDK) and opens
    # an ssh -L tunnel so its detection loop reads the box's OWN ES at localhost:<port> — each run gets its
    # own ES (no shared harness ES), fixing cross-experiment contamination + shard-cap arming failures.
    # Copied into each telemetry-consuming plugin (box_es_install.sh is co-located) so each plugin is
    # self-contained — no shared base method or helper module.
    @staticmethod
    def _es_tunnel_pidfile(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "es_tunnel.pid"

    def prepare_box_es(self, box_cfg: dict, experiment_name: str, cfg: ExperimentManagerConfig) -> dict:
        """Install ES on the defender box (idempotent) and open a harness-host->box:9200 ssh -L tunnel.
        Takes box_cfg ({defender_env_spec, defender_setup_access} — the env-produced box inventory + access,
        NOT a written config, so it can run BEFORE build_config) and RETURNS {es_url, falco_index,
        sysflow_index}; build_config() bakes those in. Drops an es_tunnel.pid for teardown. Fail-closed:
        raises if the topology has no defender box — box ES is required, no shared-harness-ES fallback."""
        import shlex
        import socket
        import time

        cfgd = box_cfg
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

        return {"es_url": es_url, "falco_index": "falco", "sysflow_index": "sysflow"}

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
