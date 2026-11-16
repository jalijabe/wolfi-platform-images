"""Reduce ASH's SARIF to what ASH itself counts as actionable, for GitHub code
scanning.

GitHub code scanning ignores SARIF ``suppressions``, so every finding that ASH
suppressed with a written reason (``.ash/.ash.yaml``, or a scanner's own
annotated skip) would reappear as an open alert, as would every finding below
ASH's severity threshold. This keeps only results that are unsuppressed and at
SARIF level ``error`` or ``warning`` (ASH's MEDIUM threshold and above); the
complete SARIF, suppressions and justifications included, stays in the
``ash-reports`` artifact.

Usage: python -m imagefactory.sariffilter <ash.sarif> <out.sarif>
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ACTIONABLE_LEVELS = frozenset({"error", "warning"})


def actionable(result: dict[str, Any]) -> bool:
    return not result.get("suppressions") and result.get("level", "warning") in ACTIONABLE_LEVELS


def filter_sarif(sarif: dict[str, Any]) -> tuple[dict[str, Any], int, int]:
    """Return (filtered SARIF, results kept, results dropped)."""
    kept = dropped = 0
    runs = []
    for run in sarif.get("runs", []):
        results = run.get("results", [])
        keep = [r for r in results if actionable(r)]
        kept += len(keep)
        dropped += len(results) - len(keep)
        runs.append({**run, "results": keep})
    return {**sarif, "runs": runs}, kept, dropped


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = Path(args[0]), Path(args[1])
    out, kept, dropped = filter_sarif(json.loads(src.read_text()))
    dst.write_text(json.dumps(out) + "\n")
    print(f"sariffilter: kept {kept} actionable; left {dropped} suppressed or below threshold in {src}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
