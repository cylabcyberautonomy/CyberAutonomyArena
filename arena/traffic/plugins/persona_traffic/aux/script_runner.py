#!/usr/bin/env python3
"""bgtraffic script runner: weighted command groups fired as a Poisson process. STDLIB ONLY.

Shipped to each host by the persona_traffic plugin's ``script`` generator kind and run as a systemd
unit. One event = one group: its commands run in order with human-like think time between them, each
either directly (``entry: direct``, the unit runs as the actor's user) or through an SSH login to the
actor's user on this very host (``entry: ssh``, the unit runs as root with ``--ssh-key``), so the process
ancestry a sensor sees is sshd -> bash -> command.

Spec (JSON):
  name              unique per host; the unit is bgtraffic-<name>
  user              the actor's login (default ubuntu)
  entry             direct | ssh (default direct)
  events_per_hour   Poisson rate of events (groups) per hour
  seed              int; makes the schedule reproducible per host
  think_seconds     mean think time between a group's commands (default 4; log-normal, clamped)
  command_timeout   seconds per command (default 60)
  vars              {NAME: [choices]}: one choice per event, substituted as ${NAME} in commands
  groups            [{label, weight, commands: [shell strings]}]

Every command appends one JSON line to --log: the benign ground truth for scoring.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import os
import random
import re
import signal
import string
import subprocess
import sys
import time

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ENTRIES = ("direct", "ssh")
_stop = False


def validate(spec: dict) -> list[str]:
    problems = []
    name = spec.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        problems.append(f"name {name!r} must match {NAME_RE.pattern}")
    if spec.get("entry", "direct") not in ENTRIES:
        problems.append(f"entry must be one of {ENTRIES}")
    rate = spec.get("events_per_hour")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) or rate <= 0:
        problems.append("events_per_hour must be a number > 0")
    for k, v in (spec.get("vars") or {}).items():
        if not isinstance(v, list) or not v:
            problems.append(f"vars.{k} must be a non-empty list")
    groups = spec.get("groups")
    if not isinstance(groups, list) or not groups:
        problems.append("groups must be a non-empty list")
    else:
        for i, g in enumerate(groups):
            if not isinstance(g, dict) or not isinstance(g.get("commands"), list) or not g["commands"]:
                problems.append(f"groups[{i}] needs a non-empty commands list")
            w = (g or {}).get("weight", 1.0) if isinstance(g, dict) else 1.0
            if not isinstance(w, (int, float)) or w <= 0:
                problems.append(f"groups[{i}].weight must be > 0")
    return problems


def _on_term(signum, frame):  # noqa: ARG001
    global _stop
    _stop = True


def _sleep(seconds: float) -> None:
    """Sleep in short slices so SIGTERM is honoured promptly."""
    end = time.monotonic() + seconds
    while not _stop:
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(left, 1.0))


def _think(rng: random.Random, mean: float) -> float:
    # log-normal with the requested mean and a moderate spread; clamped so a session never stalls
    sigma = 0.6
    mu = math.log(mean) - sigma * sigma / 2
    return max(0.2, min(rng.lognormvariate(mu, sigma), 60.0))


def _choose_group(rng: random.Random, groups: list[dict]) -> dict:
    weights = [float(g.get("weight", 1.0)) for g in groups]
    return rng.choices(groups, weights=weights, k=1)[0]


def _substitute(cmd: str, chosen: dict) -> str:
    return string.Template(cmd).safe_substitute({k: str(v) for k, v in chosen.items()})


def _argv(cmd: str, entry: str, user: str, ssh_key: str | None) -> list[str]:
    if entry == "ssh":
        return ["ssh", "-i", ssh_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
                f"{user}@127.0.0.1", "--", cmd]
    return ["bash", "-lc", cmd]


def run_event(spec: dict, rng: random.Random, log, ssh_key: str | None) -> None:
    entry = spec.get("entry", "direct")
    user = spec.get("user", "ubuntu")
    timeout = float(spec.get("command_timeout", 60))
    think = float(spec.get("think_seconds", 4))
    chosen = {k: rng.choice(v) for k, v in (spec.get("vars") or {}).items()}
    group = _choose_group(rng, spec["groups"])
    label = group.get("label", "")
    for i, raw in enumerate(group["commands"]):
        if _stop:
            return
        cmd = _substitute(raw, chosen)
        started = time.monotonic()
        ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
        try:
            res = subprocess.run(_argv(cmd, entry, user, ssh_key), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=timeout)
            rc = res.returncode
        except subprocess.TimeoutExpired:
            rc = -1
        except OSError:
            rc = -2
        log.write(json.dumps({"ts": ts, "generator": spec["name"], "label": label, "entry": entry,
                              "user": user, "command": cmd, "rc": rc,
                              "seconds": round(time.monotonic() - started, 3)}) + "\n")
        log.flush()
        if i + 1 < len(group["commands"]):
            _sleep(_think(rng, think))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--log", default=None, help="activity log (JSON lines); default stdout")
    ap.add_argument("--ssh-key", default=None, help="private key for entry: ssh")
    ap.add_argument("--check", action="store_true", help="validate the spec (and the key for entry: ssh) and exit")
    ap.add_argument("--once", action="store_true", help="fire one event immediately and exit (testing)")
    args = ap.parse_args(argv)

    with open(args.spec) as f:
        spec = json.load(f)
    problems = validate(spec)
    if spec.get("entry", "direct") == "ssh":
        if not args.ssh_key:
            problems.append("entry: ssh needs --ssh-key")
        elif not os.path.exists(args.ssh_key):
            problems.append(f"ssh key {args.ssh_key} not found")
    if problems:
        print("script_runner: invalid spec: " + "; ".join(problems), file=sys.stderr)
        return 2
    if args.check:
        return 0

    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    rng = random.Random(spec.get("seed", 0))
    rate_per_sec = float(spec["events_per_hour"]) / 3600.0
    log = open(args.log, "a") if args.log else sys.stdout
    try:
        while not _stop:
            if not args.once:
                _sleep(rng.expovariate(rate_per_sec))
                if _stop:
                    break
            run_event(spec, rng, log, args.ssh_key)
            if args.once:
                break
    finally:
        if log is not sys.stdout:
            log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
