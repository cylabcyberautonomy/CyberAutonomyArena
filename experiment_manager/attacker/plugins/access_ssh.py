"""Shared SSH transport for attacker plugins that run ON their foothold (CAI, Terminus).

Environment-agnostic: the attacker reaches its foothold using the SetupAccess the arena attached
(env-produced) — host/user/port/key + opaque routing (bastion ProxyCommand / relay / direct) — NOT
by assuming an MHBench Kali box or reading MHBench config. Works for whatever foothold the
environment provides (a Kali box, a bare box, or a compromised user account on a victim).
"""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from ..env_spec import SetupAccess
from ...experiment_log import output_root

_ACCESS_FILE = "setup_access.json"


def primary_access(experiment) -> SetupAccess:
    """The foothold the attacker operates from — the first SetupAccess the arena attached."""
    access = getattr(experiment, "_attacker_access", None)
    if not access:
        raise RuntimeError("no SetupAccess on the experiment — the arena must attach it before setup")
    return access[0]


def _access_path(experiment_name: str, cfg) -> Path:
    return output_root(experiment_name, cfg) / experiment_name / "attacker" / _ACCESS_FILE


def persist_primary_access(experiment, cfg) -> SetupAccess:
    """Write the foothold access to the attacker output dir so start()/stop()/collect_logs() — which
    only receive experiment_name, not the experiment — can recover it by name. Call from setup()."""
    fa = primary_access(experiment)
    p = _access_path(experiment.experiment_name, cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(fa.model_dump()))
    return fa


def load_primary_access(experiment_name: str, cfg) -> SetupAccess:
    """Recover the foothold access persisted by setup()."""
    return SetupAccess.model_validate(json.loads(_access_path(experiment_name, cfg).read_text()))


def ssh_base(fa: SetupAccess) -> list[str]:
    """An ssh command prefix that runs a remote command on the foothold `fa`, using its env-provided
    routing (fa.ssh_common_args carries the ProxyCommand / relay opts; empty = directly reachable)."""
    cmd = ["ssh"]
    if fa.ssh_key:
        cmd += ["-i", os.path.expanduser(fa.ssh_key)]
    cmd += [
        "-p", str(fa.port),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=10",
    ]
    if fa.ssh_common_args:
        cmd += shlex.split(fa.ssh_common_args)  # env-owned routing (e.g. -o ProxyCommand="...")
    cmd += [f"{fa.user}@{fa.host}"]
    return cmd
