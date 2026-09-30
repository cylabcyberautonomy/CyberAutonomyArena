"""Runs on the foothold box. Drives harbor's Terminus-2 agent against a LOCAL shell (this box) with
the attack objective — so the shell the agent types into has east-west access to the victims.

Terminus-2 (harbor) normally runs inside a Docker task container it creates. Here we instead give it
a minimal BaseEnvironment whose exec() runs commands locally on the foothold, so no container is
needed and the agent operates the real attacker box (in-context execution as the granted principal —
no nested shell / DinD). The agent flow is:
    Terminus2(logs_dir, model_name, api_base, max_turns, record_terminal_session=False)
    await agent.setup(env)                      # builds a TmuxSession bound to env (execs tmux locally)
    await agent.run(instruction, env, context)  # read-terminal -> LLM -> type-command loop

The LocalShellEnvironment <-> Terminus-2 contract is checked by an on-box probe
(tests/README_live_smoke.md) that runs agent.setup(env) and drives one command through the tmux
session WITHOUT the LLM. harbor's BaseEnvironment is a large abstract class, but Terminus-2/TmuxSession
only touch a small slice of it: default_user, exec(), and (skills/recording only)
is_dir()/upload_file()/trial_paths. We override __init__ to skip the container/resource/network
machinery and implement exactly that slice. Recording is disabled (it would additionally need a
TrialPaths + asciinema on the box); the tmux pane log and the agent context still capture the full
session.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from harbor.agents.terminus_2.terminus_2 import Terminus2
from harbor.environments.base import BaseEnvironment, ExecResult
from harbor.models.agent.context import AgentContext
from harbor.models.trial.paths import EnvironmentPaths


class LocalShellEnvironment(BaseEnvironment):
    """Minimal harbor environment whose exec() runs on THIS host (the foothold). No Docker, no
    container — the agent operates the real attacker box directly, as the granted principal.
    Overrides __init__ so none of the base container/resource/network machinery is needed; the
    concrete BaseEnvironment helpers Terminus-2 uses (e.g. is_dir) are inherited and route through
    exec()."""

    def __init__(self, default_user: str | None = None):
        import logging
        self._logger = logging.getLogger("terminus.local_env")
        # attributes Terminus-2 / TmuxSession / inherited helpers may read:
        self.default_user = default_user       # None -> run as the current (login) principal
        self.trial_paths = None                # only read when record_terminal_session=True
        self.environment_name = "local-foothold"
        self.session_id = "local-foothold__attacker"
        self._env_id = "local-foothold"

    # --- the slice Terminus-2 / TmuxSession actually use ----------------------------------
    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None) -> ExecResult:
        # `user` is intentionally ignored: in-context execution — we already run AS the granted
        # principal (root on the foothold via `ssh root@foothold`), so there is no user to switch to.
        merged = {**os.environ, **(env or {})}
        try:
            p = subprocess.run(["bash", "-lc", command], capture_output=True, text=True,
                               cwd=cwd, env=merged, timeout=timeout_sec)
            return ExecResult(stdout=p.stdout, stderr=p.stderr, return_code=p.returncode)
        except subprocess.TimeoutExpired as e:
            so = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            return ExecResult(stdout=so, stderr=f"timeout after {timeout_sec}s", return_code=124)

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

    async def start(self, force_build=False):
        # TmuxSession pipes the pane into EnvironmentPaths.agent_dir; create the in-env log dirs so
        # that redirect (`cat > /logs/agent/terminus_2.pane`) succeeds. Nothing to build otherwise.
        for d in (EnvironmentPaths.agent_dir, EnvironmentPaths.verifier_dir):
            subprocess.run(["bash", "-lc", f"mkdir -p {d} && chmod 777 {d}"],
                           capture_output=True, text=True)
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

    agent = Terminus2(
        logs_dir=out,
        model_name=cfg["model"],
        api_base=cfg.get("api_base"),
        max_turns=cfg.get("max_turns", 1000),
        record_terminal_session=False,  # recording also needs TrialPaths + asciinema
    )
    env = LocalShellEnvironment(default_user=None)
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
