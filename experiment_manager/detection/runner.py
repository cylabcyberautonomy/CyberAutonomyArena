"""Run Sigma detections over an experiment's collected host logs.

The collection stage (MHBench `collect`) drops each host's ground-truth auditd log at
`output/<exp>/environment/<host>/audit.log`. This module runs Zircolite — which matches the
shipped Sigma Linux ruleset against raw auditd `.log` files — over every host, then aggregates
the per-host hits into one experiment-level report (JSON + human-readable Markdown), including a
MITRE ATT&CK technique rollup.

Design (per repo automation philosophy): the only genuine input is *which experiment* to score.
Everything else (locating hosts, choosing the ruleset, per-host invocation, aggregation) is
codified here. The one step that can't be automated — installing Zircolite — is detected; if it
is missing we abort with the exact commands to run, rather than proceeding in a degraded state.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import ExperimentManagerConfig

# Every line of an auditd event carries the same `msg=audit(<epoch>.<ms>:<serial>)` stamp, so
# filtering line-by-line on this epoch keeps whole multi-line events (SYSCALL/EXECVE/PATH/...) together.
_AUDIT_TS_RE = re.compile(r"audit\((\d+\.\d+):\d+\)")


class DetectionSetupError(RuntimeError):
    """Raised when Zircolite (the one-time manual setup) is not installed. Carries a
    copy-pasteable remediation so the caller never has to remember how to fix it."""


def _require_zircolite(cfg: ExperimentManagerConfig) -> tuple[Path, Path, list[Path]]:
    """Detect-if-done for the one-time Zircolite install. Returns (zircolite.py, python, rulesets)
    where rulesets is the stock Linux ruleset followed by our custom MHBench Sigma rules. Aborts
    with precise install instructions if Zircolite is missing."""
    zdir = cfg.zircolite_dir
    zpy = cfg.get_zircolite_python()
    script = zdir / "zircolite.py"
    ruleset = zdir / cfg.sigma_ruleset
    missing = []
    if not script.exists():
        missing.append(f"  Zircolite checkout not found at {zdir}")
    if not zpy.exists():
        missing.append(f"  Zircolite venv python not found at {zpy}")
    if not ruleset.exists() and script.exists():
        missing.append(f"  Sigma ruleset not found at {ruleset}")
    if missing:
        raise DetectionSetupError(
            "Detection requires Zircolite (Sigma-over-auditd). Set it up once:\n\n"
            f"  git clone --depth 1 https://github.com/wagga40/Zircolite.git {zdir}\n"
            f"  cd {zdir} && uv venv .venv && uv pip install -p .venv/bin/python -r requirements.txt\n\n"
            "Then re-run detection. Detected problems:\n" + "\n".join(missing)
        )
    # Stock ruleset first, then each custom Sigma .yml (Zircolite converts native Sigma on the fly).
    rulesets = [ruleset]
    rulesets += sorted(cfg.custom_sigma_rules_dir.glob("*.yml"))
    return script, zpy, rulesets


def _read_attack_window(experiment_name: str, cfg: ExperimentManagerConfig) -> Optional[tuple[float, float]]:
    """Return the attacker (start, end) epoch window from experiment_result.json, or None if it
    can't be determined (so scoring falls back to the full log rather than silently dropping data)."""
    result_path = cfg.output_dir / experiment_name / "experiment" / "experiment_result.json"
    if not result_path.exists():
        return None
    try:
        att = json.loads(result_path.read_text()).get("attacker", {})
        start, end = att.get("started_at"), att.get("finished_at")
    except (json.JSONDecodeError, ValueError, AttributeError):
        return None
    if start is None or end is None or end < start:
        return None
    return float(start), float(end)


def _scope_audit_log(audit_log: Path, dest: Path, window: tuple[float, float]) -> tuple[int, int]:
    """Write only the audit records whose `audit(<epoch>:...)` stamp falls within `window` to
    `dest`. Lines without a parseable stamp (rare continuation lines) are kept, so an event is
    never split. Returns (kept_lines, total_lines)."""
    start, end = window
    kept = total = 0
    with open(audit_log, errors="replace") as src, open(dest, "w") as out:
        for line in src:
            total += 1
            m = _AUDIT_TS_RE.search(line)
            if m is None:
                out.write(line)  # no stamp: keep, don't orphan a multi-line event
                kept += 1
                continue
            ts = float(m.group(1))
            if start <= ts <= end:
                out.write(line)
                kept += 1
    return kept, total


@dataclass
class HostResult:
    host: str
    audit_log: Path
    detections_path: Optional[Path]
    rules_matched: int
    events_matched: int
    error: Optional[str] = None
    events_in_window: Optional[int] = None  # audit lines kept after scoping (None = unscoped)
    events_total: Optional[int] = None


def _run_host(
    host_dir: Path,
    out_dir: Path,
    script: Path,
    zpy: Path,
    rulesets: list[Path],
    window: Optional[tuple[float, float]] = None,
) -> HostResult:
    host = host_dir.name
    audit_log = host_dir / "audit.log"
    if not audit_log.exists():
        return HostResult(host, audit_log, None, 0, 0, error="no audit.log")

    det_path = out_dir / f"{host}.json"
    zircolite_log = out_dir / f"{host}.zircolite.log"

    # Scope to the attack window so provisioning/teardown activity (which runs the same benign
    # commands on every host) isn't scored as attacker behavior. Fall back to the full log if the
    # window is unknown.
    events_in_window = events_total = None
    scan_target = audit_log
    if window is not None:
        scoped = out_dir / f"{host}.scoped.log"
        events_in_window, events_total = _scope_audit_log(audit_log, scoped, window)
        scan_target = scoped

    # --auditd: parse raw `type=... msg=audit(...)` lines. Each host is scored independently so a
    # broken log on one host can't sink the others. Multiple --ruleset flags stack the stock
    # ruleset with our custom MHBench Sigma rules.
    cmd = [str(zpy), str(script), "--events", str(scan_target), "--auditd", "--outfile", str(det_path)]
    for rs in rulesets:
        cmd += ["--ruleset", str(rs)]
    with open(zircolite_log, "w") as lf:
        proc = subprocess.run(cmd, cwd=str(script.parent), stdout=lf, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        return HostResult(host, audit_log, None, 0, 0, error=f"zircolite exit {proc.returncode} (see {zircolite_log})",
                          events_in_window=events_in_window, events_total=events_total)

    rules_matched = events_matched = 0
    if det_path.exists():
        try:
            data = json.loads(det_path.read_text())
            rules_matched = len(data)
            events_matched = sum(int(r.get("count", 0)) for r in data)
        except (json.JSONDecodeError, ValueError):
            pass
    return HostResult(host, audit_log, det_path, rules_matched, events_matched,
                      events_in_window=events_in_window, events_total=events_total)


def _aggregate(results: list[HostResult], out_dir: Path, window: Optional[tuple[float, float]]) -> dict:
    """Fold per-host detection files into one experiment-level rollup: per-rule counts across
    hosts, and a MITRE ATT&CK technique tally derived from each rule's `attack.tXXXX` tags."""
    rules: dict[str, dict] = {}
    attack: dict[str, int] = defaultdict(int)
    for r in results:
        if not r.detections_path or not r.detections_path.exists():
            continue
        try:
            data = json.loads(r.detections_path.read_text())
        except (json.JSONDecodeError, ValueError):
            continue
        for rule in data:
            title = rule.get("title", "<untitled>")
            count = int(rule.get("count", 0))
            entry = rules.setdefault(title, {
                "title": title,
                "level": rule.get("rule_level", "unknown"),
                "tags": rule.get("tags", []),
                "total_count": 0,
                "hosts": {},
            })
            entry["total_count"] += count
            entry["hosts"][r.host] = entry["hosts"].get(r.host, 0) + count
            for tag in rule.get("tags", []):
                if tag.startswith("attack.t"):
                    attack[tag.replace("attack.", "").upper()] += count

    summary = {
        "scoping": (
            {"mode": "attack_window", "start": window[0], "end": window[1], "duration_s": round(window[1] - window[0], 1)}
            if window is not None else
            {"mode": "full_log", "note": "attacker start/end unavailable; scored the whole log (includes provisioning/teardown activity)"}
        ),
        "hosts": [
            {
                "host": r.host,
                "rules_matched": r.rules_matched,
                "events_matched": r.events_matched,
                "events_in_window": r.events_in_window,
                "events_total": r.events_total,
                "error": r.error,
            }
            for r in results
        ],
        "rules": sorted(rules.values(), key=lambda e: -e["total_count"]),
        "attack_techniques": dict(sorted(attack.items(), key=lambda kv: -kv[1])),
        "totals": {
            "hosts_scored": sum(1 for r in results if r.error is None),
            "hosts_with_hits": sum(1 for r in results if r.rules_matched > 0),
            "distinct_rules": len(rules),
            "total_events_matched": sum(r.events_matched for r in results),
        },
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    _write_markdown(summary, out_dir / "summary.md")
    return summary


def _write_markdown(summary: dict, path: Path) -> None:
    t = summary["totals"]
    sc = summary["scoping"]
    if sc["mode"] == "attack_window":
        scope_line = f"- Scoping: **attack window** ({sc['duration_s']}s; audit records outside the attacker's run were excluded)"
    else:
        scope_line = f"- Scoping: **full log** ⚠️ {sc['note']}"
    lines = [
        "# Detection summary",
        "",
        scope_line,
        f"- Hosts scored: **{t['hosts_scored']}** ({t['hosts_with_hits']} with hits)",
        f"- Distinct Sigma rules fired: **{t['distinct_rules']}**",
        f"- Total matched events: **{t['total_events_matched']}**",
        "",
        "## Per-host",
        "",
        "| Host | Rules matched | Events matched | Audit lines (in-window/total) | Note |",
        "|---|---:|---:|---:|---|",
    ]
    for h in summary["hosts"]:
        if h["events_in_window"] is not None:
            win = f"{h['events_in_window']}/{h['events_total']}"
        else:
            win = "—"
        lines.append(f"| {h['host']} | {h['rules_matched']} | {h['events_matched']} | {win} | {h['error'] or ''} |")

    lines += ["", "## Rules fired (across all hosts)", "",
              "| Level | Rule | Events | Hosts |", "|---|---|---:|---|"]
    for r in summary["rules"]:
        hosts = ", ".join(f"{h}({c})" for h, c in sorted(r["hosts"].items(), key=lambda kv: -kv[1]))
        lines.append(f"| {r['level']} | {r['title']} | {r['total_count']} | {hosts} |")

    if summary["attack_techniques"]:
        lines += ["", "## MITRE ATT&CK techniques (by matched events)", "",
                  "| Technique | Events |", "|---|---:|"]
        for tech, count in summary["attack_techniques"].items():
            lines.append(f"| {tech} | {count} |")

    path.write_text("\n".join(lines) + "\n")


def run_detections(
    experiment_name: str,
    cfg: ExperimentManagerConfig,
    env_dir: Optional[Path] = None,
) -> dict:
    """Score one experiment's collected host logs against the Sigma Linux ruleset.

    Writes per-host detections + `summary.json` / `summary.md` under
    `output/<exp>/detections/`. Returns the summary dict. Raises DetectionSetupError (with a
    copy-pasteable fix) if Zircolite is not installed."""
    script, zpy, rulesets = _require_zircolite(cfg)

    if env_dir is None:
        env_dir = cfg.output_dir / experiment_name / "environment"
    if not env_dir.is_dir():
        raise FileNotFoundError(
            f"No collected host logs at {env_dir}. Run the experiment (with collection) first."
        )

    out_dir = cfg.output_dir / experiment_name / "detections"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Scope to the attacker's run window when we can determine it; otherwise score the full log.
    window = _read_attack_window(experiment_name, cfg)

    host_dirs = sorted(p for p in env_dir.iterdir() if p.is_dir())
    results = [_run_host(hd, out_dir, script, zpy, rulesets, window) for hd in host_dirs]
    return _aggregate(results, out_dir, window)
