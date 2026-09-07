#!/usr/bin/env python3
"""Score an experiment's collected host logs with the Sigma Linux ruleset (via Zircolite).

Usage:
    uv run python detect.py <experiment_name> [<experiment_name> ...]
    uv run python detect.py --all        # score every experiment that has collected logs

Writes per-host detections + summary.json/summary.md under output/<exp>/detections/.
"""
from __future__ import annotations

import argparse
import sys

from experiment_manager.config import ExperimentManagerConfig
from experiment_manager.detection import run_detections, DetectionSetupError


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("experiments", nargs="*", help="Experiment name(s) under output/")
    ap.add_argument("--all", action="store_true", help="Score every experiment with collected logs")
    args = ap.parse_args()

    cfg = ExperimentManagerConfig.load()

    names = list(args.experiments)
    if args.all:
        names = sorted(
            p.parent.name
            for p in cfg.output_dir.glob("*/environment")
            if p.is_dir()
        )
    if not names:
        ap.error("give one or more experiment names, or --all")

    rc = 0
    for name in names:
        print(f"\n=== {name} ===")
        try:
            summary = run_detections(name, cfg)
        except DetectionSetupError as e:
            print(e, file=sys.stderr)
            return 2  # setup problem is global; stop rather than repeat it per experiment
        except FileNotFoundError as e:
            print(f"  skipped: {e}", file=sys.stderr)
            rc = 1
            continue
        t = summary["totals"]
        print(f"  {t['hosts_with_hits']}/{t['hosts_scored']} hosts with hits | "
              f"{t['distinct_rules']} rules | {t['total_events_matched']} events")
        print(f"  report: output/{name}/detections/summary.md")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
