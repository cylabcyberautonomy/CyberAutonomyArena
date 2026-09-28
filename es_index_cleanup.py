#!/usr/bin/env python3
"""Reap Elasticsearch falco-<exp>/sysflow-<exp> indices for TERMINAL MHBench runs so the single-node
ES never refills to its shard cap and blocks new defenders from arming.
See memory: es-shard-cap-blocks-defender-arming.

SAFETY (fail-safe by design):
  * The :8000 (OpenStack) manager — the source of these indices — MUST be reachable, else we abort
    without deleting anything (can't confirm which runs are live).
  * An index is deleted ONLY when its experiment is:
      - explicitly TERMINAL (Finished/TimedOut/Blocked/Error) in a reachable registry, OR
      - absent from EVERY reachable registry AND its index is older than MIN_AGE_S (backstop for the
        post-clean-slate / manager-briefly-down window; MIN_AGE comfortably exceeds a run's full
        arm->attack(<=46m)->collect lifecycle).
  * An experiment that is non-terminal (active/queued/retrying/...) in ANY reachable registry is never
    touched — deleting a live index would blind a running defender.
Run with --dry-run to preview. Idempotent; safe to cron.
"""
import json, urllib.request, time, sys, datetime

ES = "http://127.0.0.1:9200"
PRIMARY = "http://127.0.0.1:8000/experiments"                 # OpenStack — must be reachable
SECONDARY = ["http://127.0.0.1:8001/experiments", "http://127.0.0.1:8002/experiments"]  # GCP — best effort
TERMINAL = {"Finished", "TimedOut", "Blocked", "Error"}
# Grace period: keep a TERMINAL run's falco-/sysflow- index this long after completion so its raw
# Falco alerts stay queryable in ES for immediate post-run analysis (the index is the only queryable
# copy). ES has ample headroom (~500/2000 shards), so there's no need to reap aggressively — only the
# backlog and anything past the grace window. Raise/lower to trade shard pressure vs. queryable window.
TERMINAL_GRACE_S = 6 * 60 * 60                               # 6h
MIN_AGE_S = 120 * 60                                          # 2h backstop for unknown-to-all indices
DRY = "--dry-run" in sys.argv


def _get(url, timeout=15):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _rows(d):
    return d if isinstance(d, list) else d.get("experiments", [])


def main():
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # 1. primary MUST be reachable
    try:
        prim = _rows(_get(PRIMARY))
    except Exception as e:
        print(f"{stamp} es-cleanup: ABORT — :8000 unreachable ({e}); nothing deleted")
        return 0
    active, terminal, reachable = set(), set(), 1
    for x in prim:
        n, st = x.get("experiment_name"), x.get("status")
        if n:
            (terminal if st in TERMINAL else active).add(n)
    for m in SECONDARY:
        try:
            e = _rows(_get(m)); reachable += 1
        except Exception:
            continue
        for x in e:
            n, st = x.get("experiment_name"), x.get("status")
            if n:
                (terminal if st in TERMINAL else active).add(n)
    terminal -= active  # active on ANY manager wins

    # 2. list candidate indices
    try:
        idx = _get(f"{ES}/_cat/indices/falco-*,sysflow-*?h=index,creation.date&format=json")
    except Exception as e:
        print(f"{stamp} es-cleanup: ES list failed ({e}); nothing deleted")
        return 1

    now_ms = time.time() * 1000
    to_delete = []
    for row in idx:
        name = row.get("index", "")
        exp = name.split("-", 1)[1] if "-" in name else ""
        if not exp or exp in active:            # live run -> never touch
            continue
        age_s = (now_ms - float(row.get("creation.date", 0))) / 1000
        if exp in terminal and age_s > TERMINAL_GRACE_S:
            to_delete.append((name, "terminal", age_s))
        elif exp not in terminal and age_s > MIN_AGE_S:   # unknown to every registry + old -> abandoned
            to_delete.append((name, "orphan-old", age_s))

    # 3. delete
    deleted = 0
    for name, reason, age_s in to_delete:
        if DRY:
            print(f"  [dry] {name}  ({reason}, age {age_s/60:.0f}m)")
            continue
        try:
            urllib.request.urlopen(urllib.request.Request(f"{ES}/{name}", method="DELETE"), timeout=15).read()
            deleted += 1
        except Exception as e:
            print(f"  FAILED delete {name}: {e}")
    print(f"{stamp} es-cleanup: managers={reachable} active={len(active)} terminal={len(terminal)} "
          f"candidates={len(to_delete)} deleted={0 if DRY else deleted}{' (dry-run)' if DRY else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
