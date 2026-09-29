"""Runs on the Kali box. Drives harbor's Terminus-2 agent against a LOCAL shell (this box) with the
attack objective — so the shell the agent types into has east-west access to the victims.

Terminus-2 (harbor) normally runs inside a Docker task container it creates. Here we instead give it
a minimal BaseEnvironment whose exec() runs commands locally on Kali, so no container is needed and
the agent operates the real attacker box. The agent flow is:
    Terminus2(logs_dir, model_name, api_base, max_turns)
    await agent.setup(env)                      # builds a TmuxSession bound to env (execs tmux locally)
    await agent.run(objective, env, context)    # read-terminal -> LLM -> type-command loop

STATUS: FIRST CUT — NOT yet validated on a live box. harbor's BaseEnvironment is a heavy abstract
class (start/stop/upload/download/exec + resource/network machinery); this LocalShellEnvironment
overrides __init__ to skip the container machinery and implements only what TmuxSession/Terminus-2
actually touch (exec + file transfer). The exact set of attributes the agent reads must be confirmed
by a real run on Kali — expect a small amount of iteration here.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text())
out = Path(cfg["output_dir"])
out.mkdir(parents=True, exist_ok=True)

# Credentials / model routing for litellm (harbor's terminus-2 backend).
if cfg.get("api_key"):
    _anthropic = "claude" in cfg["model"] or "anthropic" in cfg["model"]
    os.environ["ANTHROPIC_API_KEY" if _anthropic else "OPENAI_API_KEY"] = cfg["api_key"]
if cfg.get("api_base"):
    os.environ["OPENAI_API_BASE"] = cfg["api_base"]
    os.environ["OPENAI_BASE_URL"] = cfg["api_base"]

from harbor.agents.terminus_2.terminus_2 import Terminus2
from harbor.environments.base import BaseEnvironment, ExecResult
from harbor.models.agent.context import AgentContext


class LocalShellEnvironment(BaseEnvironment):
    """Minimal harbor environment whose exec() runs on THIS host (the Kali box). No Docker, no
    container — the agent operates the real attacker box directly. Overrides __init__ so none of the
    base container/resource/network machinery is needed."""

    def __init__(self, default_user: str = "root"):
        import logging
        self._logger = logging.getLogger("terminus.local_env")
        self.default_user = default_user
        self._env_id = "kali-local"

    # --- what TmuxSession / Terminus-2 actually use --------------------------------------
    async def exec(self, command, user=None, cwd=None, env=None, timeout=None, **kwargs) -> ExecResult:
        merged = {**os.environ, **(env or {})}
        try:
            p = subprocess.run(["bash", "-lc", command], capture_output=True, text=True,
                               cwd=cwd, env=merged, timeout=timeout)
            return ExecResult(stdout=p.stdout, stderr=p.stderr, return_code=p.returncode)
        except subprocess.TimeoutExpired as e:
            return ExecResult(stdout=(e.stdout or ""), stderr=f"timeout: {e}", return_code=124)

    async def upload_file(self, source_path, target_path):
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source_path, target_path)

    async def upload_dir(self, source_dir, target_dir):
        shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)

    async def download_file(self, source_path, target_path):
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source_path, target_path)

    async def download_dir(self, source_dir, target_dir):
        shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)

    async def start(self, force_build=False):  # nothing to build — it's the local host
        return None

    async def stop(self, delete=False):
        return None

    @staticmethod
    def type() -> str:
        return "local"

    def _validate_definition(self):
        return None

    @property
    def environment_id(self) -> str:
        return self._env_id


async def main() -> int:
    agent = Terminus2(
        logs_dir=out,
        model_name=cfg["model"],
        api_base=cfg.get("api_base"),
        max_turns=cfg.get("max_turns", 1000),
    )
    env = LocalShellEnvironment(default_user="root")
    context = AgentContext()
    await env.start()
    try:
        await agent.setup(env)
        await agent.run(instruction=cfg["objective"], environment=env, context=context)
    finally:
        await env.stop()

    # Persist usage + a short summary in the same layout the other attackers use.
    (out / "token_usage.json").write_text(json.dumps({
        "input_tokens": context.n_input_tokens or 0,
        "output_tokens": context.n_output_tokens or 0,
        "total_tokens": (context.n_input_tokens or 0) + (context.n_output_tokens or 0),
        "cost_usd": context.cost_usd,
    }))
    (out / "final_context.json").write_text(context.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
