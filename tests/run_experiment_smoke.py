#!/usr/bin/env python3
"""
Live end-to-end smoke test: submit ONE real experiment to a running manager, poll it to a
terminal state, and report pass/fail against concrete criteria.

This is the "does a real experiment still work across all four systems" check — the thing
`tests/test_arena_contract.py` deliberately does NOT do. Use it after a refactor, once the fast
contract test is green.

    stdlib only (urllib) — no venv needed. Run it from anywhere.

NAMED BASELINE COMBO (defaults):
    environment = equifax_small_instrumented   (instrumented: FalcoLLM needs Falco telemetry)
    attacker    = incalmo_strategy / GraphSearch
    defender    = llm_soc / FalcoLLM           (reads telemetry; deploys NO decoys)

⚠  SAFETY
    - This submits to a REAL manager and runs on the REAL cloud it controls: it spends cluster
      time and (for an LLM defender/attacker) real API credits, and takes ~an hour.
    - It does NOT start a manager. Point --url at one that is already running. Do NOT start a
      second OpenStack manager just for this: a manager's startup clean-slate wipes the shared
      cloud (all projects). To test the arena-refactor code specifically, that manager must be
      running the arena-refactor branch.
    - Requires --yes (or an interactive "yes") before it submits.

EXAMPLES
    # against an already-running manager on this host
    python3 tests/run_experiment_smoke.py --yes

    # attacker-only reachability check (no defender), keep the range up to inspect
    python3 tests/run_experiment_smoke.py --defender none --keep --yes

    # just tear a leftover smoke run down
    python3 tests/run_experiment_smoke.py --delete-only --name smoke_arena_contract
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

TERMINAL = {"Finished", "Error", "TimedOut", "Blocked"}
OUTPUT_ROOT_CANDIDATES = [
    Path.home() / "experiment_harness" / "output",
    Path(__file__).resolve().parent.parent / "output",
    Path(__file__).resolve().parent.parent / "experiment_manager" / "output",
]


def _req(method: str, url: str, body: dict | None = None, timeout: int = 30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"detail": raw}
    except urllib.error.URLError as e:
        return None, {"detail": f"cannot reach manager at {url}: {e}"}


def _find_output_dir(name: str, explicit: str | None) -> Path | None:
    roots = [Path(explicit)] if explicit else OUTPUT_ROOT_CANDIDATES
    for root in roots:
        d = root / name
        if d.exists():
            return d
    return None


def _submit(url: str, specs: dict) -> bool:
    code, resp = _req("POST", f"{url}/experiments", specs)
    if code == 201:
        print(f"  submitted (201): {specs['experiment_name']}")
        return True
    if code == 409:
        print(f"  ✗ already exists (409): {resp.get('detail')}. "
              f"Re-run with --overwrite, or --delete-only first.")
        return False
    print(f"  ✗ submit failed (HTTP {code}): {resp.get('detail')}")
    return False


def _poll(url: str, name: str, timeout_s: int, poll_s: int) -> tuple[str | None, str | None]:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        code, resp = _req("GET", f"{url}/experiments/{name}")
        if code == 404:
            print(f"  ✗ experiment vanished from the registry (404)")
            return None, "vanished"
        if code != 200:
            print(f"  … transient GET error (HTTP {code}); retrying")
            time.sleep(poll_s)
            continue
        status = resp.get("status")
        if status != last:
            print(f"  [{time.strftime('%H:%M:%S')}] status: {status}")
            last = status
        if status in TERMINAL:
            return status, resp.get("error")
        time.sleep(poll_s)
    return None, f"timed out after {timeout_s}s (last status: {last})"


def _check_outputs(name: str, expect_defender: bool, output_root: str | None) -> list[tuple[str, bool, str]]:
    """Best-effort inspection of the output tree. Returns (label, ok, detail) rows.
    Skipped gracefully if the tree isn't reachable from this host."""
    rows: list[tuple[str, bool, str]] = []
    out = _find_output_dir(name, output_root)
    if out is None:
        rows.append(("output tree", False, "not found on this host (manager may be remote) — skipping file checks"))
        return rows

    # attacker did something
    actions = out / "attacker" / "actions.json"
    n_actions = 0
    exfil = 0
    if actions.exists():
        for line in actions.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            n_actions += 1
            if "MD5SumAttackerData" in line:  # the exfil action_name Incalmo records
                exfil += 1
    rows.append(("attacker actions recorded", n_actions > 0, f"{n_actions} actions"))
    rows.append(("attacker exfil action (reached DB tier)", exfil > 0,
                 f"{exfil} MD5SumAttackerData action(s)"
                 + ("" if exfil else " — see detect.py / expected_data_hashes.py for true scoring")))

    # defender armed
    if expect_defender:
        ready = out / "defender" / "defender_ready"
        rows.append(("defender armed (defender_ready marker)", ready.exists(),
                     "present" if ready.exists() else "missing"))
        # canary defender: surface its connectivity report per-check
        report = out / "defender" / "connectivity_report.json"
        if report.exists():
            try:
                rep = json.loads(report.read_text())
                for check, res in rep.get("results", {}).items():
                    rows.append((f"connectivity: {check}", bool(res.get("ok")),
                                 res.get("detail") or res.get("note") or ""))
            except Exception as e:  # noqa: BLE001
                rows.append(("connectivity report", False, f"unreadable: {e}"))

    # host logs collected before teardown
    env_dir = out / "environment"
    collected = [p for p in env_dir.glob("*/*") ] if env_dir.exists() else []
    rows.append(("host logs collected", len(collected) > 0,
                 f"{len(collected)} files under environment/" if collected else "none"))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8000", help="running manager base URL")
    ap.add_argument("--name", default="smoke_arena_contract")
    ap.add_argument("--environment", default="environments/instrumented/equifax_small_instrumented.json")
    ap.add_argument("--attacker", default="GraphSearch", help="Incalmo strategy name")
    ap.add_argument("--defender", default="FalcoLLM",
                    help="llm_soc strategy, 'canary' for the connectivity diagnostic defender, "
                         "or 'none' for an attacker-only run")
    ap.add_argument("--traffic", default="none", help="caldera_human persona, or 'none'")
    ap.add_argument("--keep", action="store_true", help="leave the range standing (teardown=false)")
    ap.add_argument("--overwrite", action="store_true", help="replace a same-named prior run")
    ap.add_argument("--priority", type=int, default=1000, help="queue priority (higher = sooner)")
    ap.add_argument("--timeout", type=int, default=5400, help="max seconds to wait for a terminal state")
    ap.add_argument("--poll", type=int, default=20, help="seconds between status polls")
    ap.add_argument("--output-root", default=None, help="override where to look for the output tree")
    ap.add_argument("--delete-only", action="store_true", help="just DELETE --name and exit")
    ap.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    args = ap.parse_args()

    if args.delete_only:
        code, resp = _req("DELETE", f"{args.url}/experiments/{args.name}")
        print(f"DELETE {args.name}: HTTP {code} {resp.get('detail', '')}")
        return 0 if code in (200, 204, 404) else 1

    dfn = args.defender.lower()
    expect_defender = dfn != "none"
    is_canary = dfn == "canary"
    # New config shape: attacker is a (plugin + spec-file) pair. Write the bespoke spec to a file
    # and pass its path (the manager reads it). Same host as the manager, so an absolute temp path works.
    spec_dir = Path(tempfile.gettempdir()) / "mhbench_submitted_specs"
    spec_dir.mkdir(parents=True, exist_ok=True)
    attacker_spec_path = spec_dir / f"{args.name}_attacker.json"
    attacker_spec_path.write_text(json.dumps({"strategy": args.attacker}))
    specs: dict = {
        "experiment_name": args.name,
        "environment": args.environment,
        "attacker_plugin": "incalmo_strategy",
        "attacker_spec": str(attacker_spec_path),
        "teardown": not args.keep,
        "overwrite": args.overwrite,
        "priority": args.priority,
    }
    if is_canary:
        specs["defender"] = {"type": "canary"}
    elif expect_defender:
        specs["defender"] = {"type": "llm_soc", "strategy": args.defender}
    if args.traffic.lower() != "none":
        specs["traffic"] = {"type": "caldera_human", "persona": args.traffic}

    print("Live experiment smoke test")
    print(f"  manager : {args.url}")
    print(f"  spec    : {json.dumps(specs)}")
    print("  ⚠  runs on the REAL cloud this manager controls (cluster time + LLM credits).")
    if not args.yes:
        if input("  Proceed? type 'yes': ").strip().lower() != "yes":
            print("  aborted.")
            return 2

    if not _submit(args.url, specs):
        return 1

    print(f"  polling every {args.poll}s (timeout {args.timeout}s)…")
    status, err = _poll(args.url, args.name, args.timeout, args.poll)

    print("\nRESULT")
    print(f"  terminal status: {status}")
    if err:
        print(f"  error/detail   : {err}")

    rows = _check_outputs(args.name, expect_defender, args.output_root)
    for label, ok, detail in rows:
        print(f"  [{'OK ' if ok else '!! '}] {label}: {detail}")

    # PASS = reached Finished AND every hard file check that we could evaluate is OK.
    hard_ok = all(ok for label, ok, _ in rows if "not found" not in _)
    passed = status == "Finished" and hard_ok
    print(f"\n{'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
