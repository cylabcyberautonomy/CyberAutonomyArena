"""Foothold-side orchestrator for the Cairn attacker.

Standalone script pushed by cairn.py.start() to /opt/cairn/cairn_runner.py and launched inside the
Cairn repo's uv-managed venv (so `cairn` is on PATH). Reads the plugin's attacker_config.json and:

  1. writes dispatch.yaml from attacker_config (claudecode worker w/ ANTHROPIC_* env),
  2. spawns `cairn serve` + `cairn dispatch` as child processes,
  3. POSTs a new project (origin + goal) and polls /projects/{id} until status=completed/stopped,
  4. snapshots the final project detail + token-usage summary into output_dir/,
  5. shuts the children down and exits.

Not a module — it has no imports from the arena, so the arena can push it as a text blob (same as
cai_runner.py / terminus_runner.py do). Only stdlib + `requests` (a Cairn runtime dep)."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import requests
import yaml

# PATH surgery for the subprocesses we (and Cairn's dispatcher) spawn:
#  - the Cairn venv's bin: we are launched via that venv's python BY ABSOLUTE PATH, which does NOT
#    put its bin/ on PATH, so bare `cairn serve`/`cairn dispatch` would die with FileNotFoundError.
#  - ~/.local/bin: the claudecode worker's `claude` native binary installs there (see cairn.py setup).
# Prepend both so they win over any stale/broken launcher stub earlier on PATH.
os.environ["PATH"] = os.pathsep.join([
    str(Path(sys.executable).parent),
    os.path.expanduser("~/.local/bin"),
    os.environ.get("PATH", ""),
])
# The foothold runs as root; claude-code refuses `--dangerously-skip-permissions` (which Cairn's
# worker passes) under root UNLESS IS_SANDBOX=1 marks the host as a throwaway sandbox — which the
# in-env attacker VM is. Set it here so the whole runner→dispatcher→claude tree inherits it.
os.environ["IS_SANDBOX"] = "1"

CFG = json.loads(Path(sys.argv[1]).read_text())
OUT = Path(CFG["output_dir"])
OUT.mkdir(parents=True, exist_ok=True)

SERVER_URL = "http://127.0.0.1:8000"
DISPATCH_YAML = Path("/opt/cairn/dispatch.yaml")
SERVER_DB = Path("/opt/cairn/server.db")
POLL_INTERVAL_SECONDS = 10
# Headroom over the plugin's project-poll cap: shutting the children down cleanly must not race
# the arena's SIGTERM, so if we hit poll_timeout we exit non-zero but keep ourselves alive long
# enough to write the artefacts.
SHUTDOWN_GRACE_SECONDS = 30


def _write_dispatch_yaml() -> None:
    """Render dispatch.yaml for local-mode (claudecode worker)."""
    anthropic = "claude" in CFG["model"] or "anthropic" in CFG["model"]
    base_url = CFG.get("api_base") or ("https://api.anthropic.com" if anthropic else "https://api.openai.com/v1")
    key_var = "ANTHROPIC_AUTH_TOKEN" if anthropic else "OPENAI_API_KEY"
    base_var = "ANTHROPIC_BASE_URL" if anthropic else "OPENAI_BASE_URL"
    model_var = "ANTHROPIC_MODEL" if anthropic else "OPENAI_MODEL"
    doc = {
        "server": SERVER_URL,
        "runtime": {
            "execution": "local",
            "worker_healthcheck": "disabled",
            "max_workers": 3,
            "max_running_projects": 1,
            "max_project_workers": 2,
            "interval": 3,
            "healthcheck_timeout": 15,
            "prompt_group": "default",
        },
        "tasks": {
            "bootstrap": {"timeout": 300, "conclude_timeout": 60},
            "reason": {"timeout": 120},
            "explore": {"timeout": 1800, "conclude_timeout": 180},
        },
        "local": {"workspace_root": "/opt/cairn/workspaces", "completed_action": "keep"},
        "workers": [{
            "name": "local-claude",
            "type": CFG["worker"],
            "task_types": ["bootstrap", "reason", "explore"],
            "max_running": 2,
            "priority": 0,
            "env": {
                base_var: base_url,
                key_var: CFG["api_key"],
                model_var: CFG["model"],
                # Allow claude-code's --dangerously-skip-permissions under the root foothold user
                # (also set in the runner's own env above, in case Cairn builds a clean worker env).
                "IS_SANDBOX": "1",
            },
        }],
    }
    DISPATCH_YAML.write_text(yaml.safe_dump(doc, sort_keys=False))


def _wait_server_ready(deadline: float) -> None:
    """Cairn exposes no /healthz; GET /projects returns 200 w/ [] once the DB has configured."""
    last_err = None
    while time.time() < deadline:
        try:
            r = requests.get(f"{SERVER_URL}/projects", timeout=3)
            if r.status_code == 200:
                return
            last_err = f"HTTP {r.status_code}"
        except requests.RequestException as e:
            last_err = str(e)
        time.sleep(1)
    raise RuntimeError(f"cairn server did not become ready: {last_err}")


def _spawn(argv: list[str], log_name: str) -> subprocess.Popen:
    log = open(OUT / log_name, "a")
    return subprocess.Popen(
        argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, cwd="/opt/cairn"
    )


def _create_project() -> str:
    body = {
        "title": f"arena-{int(time.time())}",
        "origin": CFG["origin"],
        "goal": CFG["goal"],
        "bootstrap_enabled": True,
        "hints": [{"content": CFG["hint"], "creator": "arena"}],
    }
    r = requests.post(f"{SERVER_URL}/projects", json=body, timeout=15)
    r.raise_for_status()
    return r.json()["project"]["id"]


def _poll_until_done(project_id: str) -> dict:
    deadline = time.time() + int(CFG["project_poll_timeout_seconds"])
    last_detail: dict = {}
    while time.time() < deadline:
        try:
            r = requests.get(f"{SERVER_URL}/projects/{project_id}", timeout=10)
            if r.status_code == 200:
                detail = r.json()
                last_detail = detail
                status = detail["project"]["status"]
                if status in ("completed", "stopped"):
                    return detail
        except requests.RequestException:
            pass
        time.sleep(POLL_INTERVAL_SECONDS)
    # Timeout: return the last snapshot so the arena still has telemetry.
    return last_detail


def _snapshot(project_id: str, detail: dict) -> None:
    (OUT / "project_detail.json").write_text(json.dumps(detail, indent=2, default=str))
    # Full export (facts + intents + hints graph) — handy for the paper's post-hoc analysis.
    try:
        r = requests.get(f"{SERVER_URL}/export/{project_id}", timeout=30)
        if r.ok:
            (OUT / "project_export.json").write_text(r.text)
    except requests.RequestException:
        pass


def _terminate(child: subprocess.Popen) -> None:
    if child.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def main() -> int:
    _write_dispatch_yaml()
    # Serve stores the SQLite blackboard at /opt/cairn/server.db so collect_logs can tar it.
    server = _spawn(
        ["cairn", "serve", "--host", "127.0.0.1", "--port", "8000",
         "--db-path", str(SERVER_DB), "--no-access-log"],
        "server.log",
    )
    try:
        _wait_server_ready(time.time() + 60)
        project_id = _create_project()
        (OUT / "project_id").write_text(project_id)
        dispatcher = _spawn(
            ["cairn", "dispatch", "--config", str(DISPATCH_YAML)],
            "dispatcher.log",
        )
        try:
            detail = _poll_until_done(project_id)
            _snapshot(project_id, detail)
            status = detail.get("project", {}).get("status") if detail else None
            return 0 if status == "completed" else 2
        finally:
            _terminate(dispatcher)
    finally:
        _terminate(server)


if __name__ == "__main__":
    sys.exit(main())
