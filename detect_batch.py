#!/usr/bin/env python3
"""Batch-score external (e.g. PhDPT) MHBench experiment datasets with the detection pipeline.

Scores each experiment's collected host auditd logs against the stock Sigma Linux ruleset + our
custom MHBench rules, scoped to the attacker's run window, and aggregates per attacker model.

Resumable: an experiment already present in <out>/index.jsonl is skipped. Reads are done in place
(no copying the 164GB), so this must run with read access to the source tree (i.e. under sudo when
the source is root-owned). Outputs go to <out>, chowned back to the invoking user at the end.

Usage (under sudo for root-owned sources):
    sudo /home/lakshmi/experiment_harness/.venv/bin/python detect_batch.py \
        --source-root /root/phdpt/tools/experiment_harness/output \
        --models g k3 qwen38 \
        --out /home/lakshmi/experiment_harness/output_phdpt \
        [--limit-per-model N]
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from experiment_manager.detection.runner import _AUDIT_TS_RE, _scope_audit_log

ZIRCOLITE = Path("/home/lakshmi/Zircolite/zircolite.py")
ZPY = Path("/home/lakshmi/Zircolite/.venv/bin/python")
STOCK_RULESET = Path("/home/lakshmi/Zircolite/rules/rules_linux.json")
CUSTOM_RULESET = Path("/home/lakshmi/experiment_harness/experiment_manager/detection/mhbench_custom_ruleset.json")
SCOPE_TMP = Path("/tmp/phdpt_scope")


def _model_of(exp_name: str) -> str:
    # dissect_<model>_<abstraction>_<env>_t<n>
    parts = exp_name.split("_")
    return parts[1] if len(parts) > 1 and parts[0] == "dissect" else "?"


def _attack_window(exp_dir: Path):
    rp = exp_dir / "experiment" / "experiment_result.json"
    if not rp.exists():
        return None
    try:
        att = json.loads(rp.read_text()).get("attacker", {})
        s, e = att.get("started_at"), att.get("finished_at")
        if s is None or e is None or e < s:
            return None
        return float(s), float(e)
    except Exception:
        return None


def _score_host(audit_log: Path, window, scoped_path: Path, det_path: Path) -> dict:
    kept, total = _scope_audit_log(audit_log, scoped_path, window)
    cmd = [str(ZPY), str(ZIRCOLITE), "--events", str(scoped_path), "--auditd",
           "--outfile", str(det_path), "--ruleset", str(STOCK_RULESET), "--ruleset", str(CUSTOM_RULESET)]
    subprocess.run(cmd, cwd=str(ZIRCOLITE.parent), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    per_rule = {}
    if det_path.exists():
        try:
            for r in json.loads(det_path.read_text()):
                per_rule[r.get("title", "?")] = per_rule.get(r.get("title", "?"), 0) + int(r.get("count", 0))
        except Exception:
            pass
    scoped_path.unlink(missing_ok=True)
    det_path.unlink(missing_ok=True)
    return {"kept": kept, "total": total, "per_rule": per_rule}


def _score_experiment(exp_dir: Path) -> dict:
    name = exp_dir.name
    window = _attack_window(exp_dir)
    env = exp_dir / "environment"
    hosts = sorted(p for p in env.iterdir() if p.is_dir()) if env.is_dir() else []
    per_rule_total: dict[str, int] = defaultdict(int)
    hosts_with_hits = 0
    host_count = 0
    for hd in hosts:
        al = hd / "audit.log"
        if not al.exists():
            continue
        host_count += 1
        res = _score_host(al, window if window else (0, 9_999_999_999),
                          SCOPE_TMP / f"{name}_{hd.name}.log", SCOPE_TMP / f"{name}_{hd.name}.json")
        if res["per_rule"]:
            hosts_with_hits += 1
        for t, c in res["per_rule"].items():
            per_rule_total[t] += c
    return {
        "experiment": name,
        "model": _model_of(name),
        "scoped": window is not None,
        "hosts": host_count,
        "hosts_with_hits": hosts_with_hits,
        "distinct_rules": len(per_rule_total),
        "total_events": sum(per_rule_total.values()),
        "per_rule": dict(sorted(per_rule_total.items(), key=lambda kv: -kv[1])),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--models", nargs="+", default=["g", "k3", "qwen38"])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--limit-per-model", type=int, default=0, help="0 = all")
    args = ap.parse_args()

    for p in (ZIRCOLITE, ZPY, STOCK_RULESET, CUSTOM_RULESET):
        if not p.exists():
            print(f"missing prerequisite: {p}", file=sys.stderr)
            return 2

    args.out.mkdir(parents=True, exist_ok=True)
    SCOPE_TMP.mkdir(parents=True, exist_ok=True)
    index_path = args.out / "index.jsonl"
    done = set()
    if index_path.exists():
        for line in index_path.read_text().splitlines():
            try:
                done.add(json.loads(line)["experiment"])
            except Exception:
                pass

    # discover experiments per model
    todo: list[Path] = []
    for m in args.models:
        dirs = sorted(d for d in args.source_root.glob(f"dissect_{m}_*")
                      if (d / "environment").is_dir() and d.name not in done)
        if args.limit_per_model:
            dirs = dirs[:args.limit_per_model]
        todo += dirs

    print(f"{len(done)} already done; scoring {len(todo)} experiments across models {args.models}")
    t0 = time.time()
    with open(index_path, "a") as idx:
        for i, exp_dir in enumerate(todo, 1):
            ts = time.time()
            try:
                rec = _score_experiment(exp_dir)
            except Exception as e:
                rec = {"experiment": exp_dir.name, "model": _model_of(exp_dir.name), "error": str(e)}
            idx.write(json.dumps(rec) + "\n")
            idx.flush()
            dt = time.time() - ts
            print(f"[{i}/{len(todo)}] {rec['experiment']} "
                  f"({rec.get('hosts','?')}h, {rec.get('hosts_with_hits','?')} hit, "
                  f"{rec.get('total_events','?')} ev) {dt:.0f}s")

    print(f"\nTotal wall time: {time.time()-t0:.0f}s")
    _write_rollup(index_path, args.out / "rollup.md")

    # chown outputs back to the invoking (sudo) user so they're accessible without root
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            uid = pwd.getpwnam(sudo_user).pw_uid
            gid = pwd.getpwnam(sudo_user).pw_gid
            for root, dirs, files in os.walk(args.out):
                os.chown(root, uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)
        except Exception as e:
            print(f"(chown skipped: {e})")
    return 0


def _write_rollup(index_path: Path, out_md: Path) -> None:
    by_model: dict[str, list[dict]] = defaultdict(list)
    per_model_rules: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for line in index_path.read_text().splitlines():
        try:
            r = json.loads(line)
        except Exception:
            continue
        if "error" in r:
            continue
        by_model[r["model"]].append(r)
        for t, c in r.get("per_rule", {}).items():
            per_model_rules[r["model"]][t] += c

    lines = ["# PhDPT open-source model detection rollup", ""]
    lines += ["| Model | Experiments | Hosts | Hosts w/ hits | Total alerts | Alerts/exp |",
              "|---|---:|---:|---:|---:|---:|"]
    for m, recs in sorted(by_model.items()):
        exps = len(recs)
        hosts = sum(r.get("hosts", 0) for r in recs)
        hwh = sum(r.get("hosts_with_hits", 0) for r in recs)
        ev = sum(r.get("total_events", 0) for r in recs)
        lines.append(f"| {m} | {exps} | {hosts} | {hwh} | {ev} | {ev/exps:.1f} |" if exps else "")
    lines += ["", "## Top rules per model", ""]
    for m in sorted(per_model_rules):
        lines.append(f"### {m}")
        lines.append("")
        lines.append("| Rule | Alerts |")
        lines.append("|---|---:|")
        for t, c in sorted(per_model_rules[m].items(), key=lambda kv: -kv[1])[:15]:
            lines.append(f"| {t} | {c} |")
        lines.append("")
    out_md.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
