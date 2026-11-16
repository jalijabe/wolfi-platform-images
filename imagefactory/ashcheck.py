"""Verify an ASH run actually scanned (guards against silent false passes).

ASH v3.7.1 in container mode exits 0 when its image build fails and leaves any
previous run's reports in place. scripts/ash-scan.sh therefore deletes the output
directory first and runs this check afterwards: the SARIF must exist, and every
scanner must have run (status not MISSING or ERROR), except those explicitly
allowed to be missing (cdk-nag/cfn-nag need container mode).

Usage: python -m imagefactory.ashcheck .ash/ash_output [--allow-missing cdk-nag,cfn-nag]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

NOT_RUN = frozenset({"MISSING", "ERROR", "SKIPPED"})


def check(output_dir: Path, allow_missing: frozenset[str]) -> list[str]:
    """Return a list of problems; empty means the scan really ran."""
    problems: list[str] = []
    sarif = output_dir / "reports" / "ash.sarif"
    if not sarif.is_file() or sarif.stat().st_size == 0:
        problems.append(f"{sarif} is missing or empty: the scan did not run")
    agg = output_dir / "ash_aggregated_results.json"
    if not agg.is_file():
        problems.append(f"{agg} is missing: the scan did not run")
        return problems
    results = json.loads(agg.read_text(encoding="utf-8")).get("scanner_results") or {}
    if not results:
        problems.append("no scanner results recorded")
    for name, res in sorted(results.items()):
        status = str(res.get("status", "UNKNOWN")).upper()
        if res.get("excluded"):
            continue
        if status in NOT_RUN and name not in allow_missing:
            problems.append(f"scanner {name} did not run (status {status})")
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--allow-missing", default="", help="comma-separated scanners allowed not to run")
    args = ap.parse_args(argv)
    allow = frozenset(s.strip() for s in args.allow_missing.split(",") if s.strip())
    problems = check(args.output_dir, allow)
    for p in problems:
        print(f"ashcheck: {p}", file=sys.stderr)
    if problems:
        return 1
    print("ashcheck: OK (all required scanners ran)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
