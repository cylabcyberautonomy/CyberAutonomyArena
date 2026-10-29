#!/usr/bin/env python3
"""computer_use driver: a Claude computer-use agent driving a victim's desktop over SSH + xdotool.

Runs HARNESS-SIDE (launched by PersonaTraffic.start()), one process for every host that has a
``computer_use`` generator, so the model credential never reaches a victim. Per host it schedules
desktop sessions as a Poisson process; each session hands the model a task drawn from the spec, a
screenshot, and the ``computer_toolset_20260801`` toolset, then executes the member tool calls the model
returns on the host's virtual display (an mhbench ``workstation_instrumented`` host: XFCE on Xvfb :1).

Every action is logged as one JSON line (the benign ground truth), and a session can later be REPLAYED
from that log without a model (``replay_from`` in the spec), which is how later arms of an experiment get
the same desktop activity deterministically.

Hard rules the driver enforces regardless of what the model decides (``deny_patterns``,
``allowed_hosts``): typed text that matches a deny pattern or names a host outside the estate is refused
with an error tool_result, and a session with three refusals ends.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import json
import os
import random
import re
import shlex
import signal
import string
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

TOOLSET = {"type": "computer_toolset_20260801"}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_POLICY_BLOCKS = 3
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BUTTON = {"left_click": 1, "middle_click": 2, "right_click": 3, "double_click": 1, "triple_click": 1}
_SCROLL = {"up": 4, "down": 5, "left": 6, "right": 7}

RULES = (
    "\n\nYou are a real employee on your own workstation inside the company network. Work only on the task "
    "given. Use the desktop's applications (the browser for the internal web portal, the terminal for SSH "
    "to the servers you administer, the editor and spreadsheet for notes). Never run scanners or network "
    "tools, never read other users' files or system credential files, never use sudo, never touch files or "
    "hosts the task did not mention, and stop when the task is done or cannot be completed."
)

_stop = threading.Event()


# -- policy ---------------------------------------------------------------------------------------------

class Policy:
    """Hard limits on what the agent may type, independent of the model's judgement."""

    def __init__(self, deny_patterns: list[str], allowed_hosts: list[str]):
        self.deny = [re.compile(p, re.IGNORECASE) for p in deny_patterns]
        self.allowed = set(allowed_hosts)

    def check(self, member: str, inp: dict) -> Optional[str]:
        """Return a refusal reason, or None if the action is allowed."""
        if member != "type":
            return None
        text = str(inp.get("text", ""))
        for pat in self.deny:
            if pat.search(text):
                return f"blocked by traffic policy (pattern {pat.pattern!r})"
        for ip in _IPV4.findall(text):
            if self.allowed and ip not in self.allowed:
                return f"blocked by traffic policy (host {ip} is outside the estate)"
        return None


# -- the desktop, over SSH --------------------------------------------------------------------------------

def _mods(text: Optional[str]) -> list[str]:
    return [m for m in (text or "").split("+") if m]


def xdotool_argv(member: str, inp: dict) -> Optional[list[str]]:
    """The xdotool command (tokens after ``xdotool``) for a toolset member, or None for non-xdotool members."""
    if member in _BUTTON:
        argv: list[str] = []
        if inp.get("coordinate"):
            x, y = inp["coordinate"]
            argv += ["mousemove", str(int(x)), str(int(y))]
        mods = _mods(inp.get("text"))
        for m in mods:
            argv += ["keydown", m]
        repeat = {"double_click": 2, "triple_click": 3}.get(member, 1)
        argv += ["click", "--repeat", str(repeat), "--delay", "80", str(_BUTTON[member])]
        for m in reversed(mods):
            argv += ["keyup", m]
        return argv
    if member == "left_click_drag":
        sx, sy = inp["start_coordinate"]
        x, y = inp["coordinate"]
        return ["mousemove", str(int(sx)), str(int(sy)), "mousedown", "1", "mousemove", "--sync",
                str(int(x)), str(int(y)), "mouseup", "1"]
    if member == "mouse_move":
        x, y = inp["coordinate"]
        return ["mousemove", str(int(x)), str(int(y))]
    if member == "left_mouse_down":
        return ["mousedown", "1"]
    if member == "left_mouse_up":
        return ["mouseup", "1"]
    if member == "scroll":
        argv = []
        if inp.get("coordinate"):
            x, y = inp["coordinate"]
            argv += ["mousemove", str(int(x)), str(int(y))]
        mods = _mods(inp.get("text"))
        for m in mods:
            argv += ["keydown", m]
        argv += ["click", "--repeat", str(int(inp.get("scroll_amount", 1))), "--delay", "40",
                 str(_SCROLL[inp.get("scroll_direction", "down")])]
        for m in reversed(mods):
            argv += ["keyup", m]
        return argv
    if member == "key":
        return ["key", "--repeat", str(int(inp.get("repeat", 1))), "--delay", "60", "--", str(inp["text"])]
    if member == "hold_key":
        return ["keydown", str(inp["text"]), "sleep", str(float(inp.get("duration", 1))), "keyup", str(inp["text"])]
    return None


class Desktop:
    """Executes toolset members on one host's virtual display through the scoped SSH access."""

    def __init__(self, access: dict, display: str = ":1"):
        self.access = access
        self.display = display

    def _ssh(self) -> list[str]:
        a = self.access
        cmd = ["ssh"]
        if a.get("ssh_key"):
            cmd += ["-i", os.path.expanduser(a["ssh_key"])]
        cmd += ["-p", str(a.get("port", 22)), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15"]
        if a.get("ssh_common_args"):
            cmd += shlex.split(a["ssh_common_args"])
        return cmd + [f"{a.get('user', 'root')}@{a['host']}"]

    def run(self, remote: str, stdin: Optional[bytes] = None, timeout: float = 60) -> tuple[int, bytes]:
        res = subprocess.run(self._ssh() + ["--", f"DISPLAY={self.display} {remote}"], input=stdin,
                             capture_output=True, timeout=timeout)
        return res.returncode, res.stdout

    def screenshot(self, region: Optional[list] = None) -> bytes:
        area = ""
        if region:
            x0, y0, x1, y1 = [int(v) for v in region]
            area = f"-a {x0},{y0},{max(1, x1 - x0)},{max(1, y1 - y0)} "
        rc, out = self.run(f"scrot {area}-o /tmp/.cu_shot.png >/dev/null 2>&1 && cat /tmp/.cu_shot.png")
        if rc != 0 or not out.startswith(b"\x89PNG"):
            raise RuntimeError(f"screenshot failed (rc={rc})")
        return out

    def act(self, member: str, inp: dict) -> dict:
        """Run one member; return {'image': png} or {'text': str}. Raises on a transport failure."""
        if member == "screenshot":
            return {"image": self.screenshot()}
        if member == "zoom":
            return {"image": self.screenshot(inp.get("region"))}
        if member == "wait":
            time.sleep(min(float(inp.get("duration", 1)), 300))
            return {"text": "OK"}
        if member == "cursor_position":
            rc, out = self.run("xdotool getmouselocation")
            m = re.search(rb"x:(\d+) y:(\d+)", out)
            if rc != 0 or not m:
                raise RuntimeError("cursor_position failed")
            return {"text": f"X={m.group(1).decode()}, Y={m.group(2).decode()}"}
        if member == "type":
            rc, _ = self.run("xdotool type --delay 30 --file -", stdin=str(inp.get("text", "")).encode())
            if rc != 0:
                raise RuntimeError("type failed")
            return {"text": "OK"}
        argv = xdotool_argv(member, inp)
        if argv is None:
            raise ValueError(f"unknown computer toolset member {member!r}")
        rc, _ = self.run("xdotool " + " ".join(shlex.quote(t) for t in argv))
        if rc != 0:
            raise RuntimeError(f"{member} failed (xdotool rc={rc})")
        return {"text": "OK"}


# -- the agent loop -----------------------------------------------------------------------------------------

def _image_block(png: bytes) -> dict:
    return {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                        "data": base64.standard_b64encode(png).decode()}}


def _result(tool_use_id: str, outcome: dict, error: Optional[str] = None) -> dict:
    r: dict[str, Any] = {"type": "tool_result", "tool_use_id": tool_use_id, "toolset_name": "computer"}
    if error:
        r["is_error"] = True
        r["content"] = error
    elif "image" in outcome:
        r["content"] = [_image_block(outcome["image"])]
    else:
        r["content"] = outcome.get("text", "OK")
    return r


def call_model(client, spec: dict, system: str, messages: list) -> Any:
    kw = dict(model=spec["model"], max_tokens=4096, system=system, tools=[TOOLSET], messages=messages,
              output_config={"effort": spec.get("effort", "medium")})
    if spec.get("fallbacks", True):
        return client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kw)
    return client.messages.create(**kw)


class ActionLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._f = open(path, "a")
        self._lock = threading.Lock()

    def write(self, **fields) -> None:
        line = json.dumps({"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), **fields})
        with self._lock:
            self._f.write(line + "\n")
            self._f.flush()


def run_session(client, desktop: Desktop, spec: dict, task: str, policy: Policy, log: ActionLog,
                host: str, session: str) -> dict:
    """One desktop session: task + screenshot in, member tool calls executed until the model stops."""
    system = spec["persona"] + RULES
    messages: list = [{"role": "user", "content": [{"type": "text", "text": task}, _image_block(desktop.screenshot())]}]
    steps = blocks = actions = 0
    stop_reason = "max_steps"
    log.write(host=host, generator=spec["name"], session=session, event="session_start", task=task)
    while steps < spec.get("max_steps", 30) and not _stop.is_set():
        steps += 1
        resp = call_model(client, spec, system, messages)
        messages.append({"role": "assistant", "content": resp.content})   # append-only history
        if resp.stop_reason == "refusal":
            stop_reason = "refusal"
            break
        calls = [b for b in resp.content if getattr(b, "type", None) == "tool_use"
                 and getattr(b, "toolset_name", None) == "computer"]
        if not calls:
            stop_reason = resp.stop_reason or "end_turn"
            break
        results, failed = [], False
        for b in calls:
            inp = dict(b.input or {})
            if failed:
                results.append(_result(b.id, {}, "Not executed: an earlier computer action in this turn failed."))
                continue
            reason = policy.check(b.name, inp)
            if reason:
                blocks += 1
                results.append(_result(b.id, {}, reason))
                log.write(host=host, generator=spec["name"], session=session, step=steps, member=b.name,
                          input=inp, ok=False, note=reason)
                failed = True
                continue
            try:
                outcome = desktop.act(b.name, inp)
                actions += 1
                results.append(_result(b.id, outcome))
                log.write(host=host, generator=spec["name"], session=session, step=steps, member=b.name,
                          input=inp, ok=True)
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
                results.append(_result(b.id, {}, f"action failed: {e}"))
                log.write(host=host, generator=spec["name"], session=session, step=steps, member=b.name,
                          input=inp, ok=False, note=str(e))
                failed = True
        messages.append({"role": "user", "content": results})
        if blocks >= MAX_POLICY_BLOCKS:
            stop_reason = "policy"
            break
    summary = {"host": host, "generator": spec["name"], "session": session, "event": "session_end",
               "task": task, "steps": steps, "actions": actions, "policy_blocks": blocks, "stop_reason": stop_reason}
    log.write(**summary)
    return summary


def replay_session(desktop: Desktop, spec: dict, actions: list[dict], log: ActionLog, host: str, session: str) -> dict:
    """Re-execute a recorded session's actions (no model), keeping the recorded gaps, capped at 10s."""
    done, last = 0, None
    log.write(host=host, generator=spec["name"], session=session, event="session_start", replay=True)
    for a in actions:
        if _stop.is_set():
            break
        ts = _dt.datetime.fromisoformat(a["ts"])
        if last is not None:
            time.sleep(min(max((ts - last).total_seconds(), 0.0), 10.0))
        last = ts
        try:
            desktop.act(a["member"], a.get("input") or {})
            done += 1
            log.write(host=host, generator=spec["name"], session=session, member=a["member"], input=a.get("input"), ok=True, replay=True)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
            log.write(host=host, generator=spec["name"], session=session, member=a["member"], input=a.get("input"), ok=False, note=str(e), replay=True)
    summary = {"host": host, "generator": spec["name"], "session": session, "event": "session_end",
               "actions": done, "stop_reason": "replayed", "replay": True}
    log.write(**summary)
    return summary


def load_recorded_sessions(path: Path, host: str) -> list[list[dict]]:
    """Group a recorded action log into the executed action lists of each session on `host`."""
    sessions: dict[str, list[dict]] = {}
    order: list[str] = []
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("host") != host or not rec.get("member") or not rec.get("ok"):
            continue
        sessions.setdefault(rec["session"], []).append(rec)
        if rec["session"] not in order:
            order.append(rec["session"])
    return [sessions[s] for s in order]


# -- scheduling -----------------------------------------------------------------------------------------------

def _sleep(seconds: float) -> None:
    end = time.monotonic() + seconds
    while not _stop.is_set():
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(left, 1.0))


def host_loop(client, host_cfg: dict, spec: dict, log: ActionLog, lock: threading.Lock) -> None:
    host = host_cfg["name"]
    desktop = Desktop(host_cfg, spec.get("display", ":1"))
    policy = Policy(spec.get("deny_patterns") or [], spec.get("allowed_hosts") or [])
    rng = random.Random(f"{spec.get('seed', 0)}:{host}:{spec['name']}")
    recorded = load_recorded_sessions(Path(spec["replay_from"]), host) if spec.get("replay_from") else None
    n = 0
    while not _stop.is_set():
        _sleep(rng.expovariate(float(spec["sessions_per_hour"]) / 3600.0))
        if _stop.is_set():
            break
        session = f"{host}-{spec['name']}-{n:04d}"
        n += 1
        with lock:   # one session at a time on a desktop
            try:
                if recorded is not None:
                    if not recorded:
                        break
                    replay_session(desktop, spec, recorded.pop(0), log, host, session)
                else:
                    chosen = {k: rng.choice(v) for k, v in (spec.get("vars") or {}).items()}
                    task = string.Template(rng.choice(spec["tasks"])).safe_substitute({k: str(v) for k, v in chosen.items()})
                    run_session(client, desktop, spec, task, policy, log, host, session)
            except Exception as e:  # noqa: BLE001 — a lost host must not kill the other hosts' loops
                log.write(host=host, generator=spec["name"], session=session, event="session_error", note=repr(e))
                _sleep(30)


def _load_env_file(path: Optional[str]) -> None:
    if not path:
        return
    for line in Path(path).expanduser().read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="driver config written by PersonaTraffic.start()")
    args = ap.parse_args(argv)
    cfg = json.loads(Path(args.config).read_text())
    _load_env_file(cfg.get("env_file"))
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    signal.signal(signal.SIGINT, lambda *_: _stop.set())

    specs = {}
    for h in cfg["hosts"]:
        for p in h["generators"]:
            specs[p] = json.loads(Path(p).read_text())
    needs_model = any(not s.get("replay_from") for s in specs.values())
    client = None
    if needs_model:
        import anthropic  # noqa: WPS433 — harness-side only
        key_env = next((s.get("api_key_env", "ANTHROPIC_API_KEY") for s in specs.values() if not s.get("replay_from")), "ANTHROPIC_API_KEY")
        client = anthropic.Anthropic(api_key=os.environ.get(key_env)) if os.environ.get(key_env) else anthropic.Anthropic()

    log_dir = Path(cfg["log_dir"])
    threads, locks = [], {}
    for h in cfg["hosts"]:
        locks.setdefault(h["name"], threading.Lock())
        for p in h["generators"]:
            spec = specs[p]
            log = ActionLog(log_dir / f"{h['name']}-{spec['name']}.jsonl")
            t = threading.Thread(target=host_loop, args=(client, h, spec, log, locks[h["name"]]), daemon=True)
            t.start()
            threads.append(t)
    while any(t.is_alive() for t in threads) and not _stop.is_set():
        time.sleep(1)
    _stop.set()
    for t in threads:
        t.join(timeout=30)
    return 0


if __name__ == "__main__":
    sys.exit(main())
