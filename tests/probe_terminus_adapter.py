#!/usr/bin/env python3
"""On-box probe for the Terminus-2 LocalShellEnvironment adapter (no LLM, no cloud).

The terminus attacker drives harbor's Terminus-2 agent against a LOCAL shell via a minimal
`LocalShellEnvironment(BaseEnvironment)` (in experiment_manager/attacker/plugins/terminus/
terminus_runner.py). harbor's BaseEnvironment is a heavy abstract class; this probe confirms the
small slice Terminus-2/TmuxSession actually touch is satisfied by the adapter, by running the real
agent setup + one command through the tmux session WITHOUT calling the model:

    env.start()                      -> creates the in-env log dirs
    agent.setup(env)                 -> builds + starts a TmuxSession bound to the adapter (execs tmux)
    session.send_keys(echo ...)      -> the agent types into its terminal
    session.get_incremental_output() -> the agent reads its terminal back  (the core run() loop)

This is the validation the runner docstring refers to. It does NOT exercise agent.run()'s LLM loop
(that needs a model key and would be an attack loop — run that only on a real foothold).

Requirements: a venv with `harbor` installed, and `tmux` on this box. It writes to /logs/agent
(harbor's fixed in-env path); create it writable first, e.g.:
    sudo mkdir -p /logs/agent /logs/verifier && sudo chmod 777 /logs/agent /logs/verifier

Run:
    <harbor-venv>/bin/python tests/probe_terminus_adapter.py
Exit 0 = PROBE_OK.
"""
import asyncio
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

RUNNER = (Path(__file__).resolve().parent.parent / "experiment_manager" / "attacker"
          / "plugins" / "terminus" / "terminus_runner.py")


def _load_runner():
    # Load the runner module by file path: it imports only stdlib + harbor (no experiment_manager),
    # and its argv/config read now lives in main(), so importing it here is side-effect free.
    spec = importlib.util.spec_from_file_location("terminus_runner_probe", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def main() -> int:
    mod = _load_runner()
    from harbor.models.trial.paths import EnvironmentPaths

    out = Path(tempfile.mkdtemp(prefix="terminus_probe_"))
    agent = mod.Terminus2(logs_dir=out, model_name="anthropic/claude-sonnet-4-5",
                          api_base=None, max_turns=5, record_terminal_session=False)
    env = mod.LocalShellEnvironment(default_user=None)

    # tmux session name collisions from a crashed prior run would fail start(); clear defensively.
    subprocess.run(["tmux", "kill-server"], capture_output=True)

    await env.start()
    print("env.start() OK")
    await agent.setup(env)
    print(f"agent.setup(env) OK -> session: {type(agent._session).__name__}")

    sess = agent._session
    marker = "arena-probe-4242"
    await sess.send_keys(keys=[f"echo {marker}", "Enter"], block=True, min_timeout_sec=0.5)
    output = await sess.get_incremental_output()
    assert marker in output, f"marker not found in captured terminal output: {output!r}"
    print("send_keys + get_incremental_output OK (agent read its own terminal)")

    await sess.stop()
    await env.stop()
    pane = Path(str(EnvironmentPaths.agent_dir)) / "terminus_2.pane"
    print(f"in-env pane log written: {pane.exists()} ({pane.stat().st_size if pane.exists() else 0} bytes)")
    print("PROBE_OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
