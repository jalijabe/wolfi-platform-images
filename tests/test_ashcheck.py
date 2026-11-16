"""The ASH guard must fail closed: no fresh output or a scanner that did not run is a failure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from imagefactory.ashcheck import check, main


def make_output(root: Path, statuses: dict[str, str], sarif: bool = True) -> Path:
    out = root / "ash_output"
    (out / "reports").mkdir(parents=True)
    if sarif:
        (out / "reports" / "ash.sarif").write_text('{"runs": []}')
    results = {name: {"status": s, "excluded": False} for name, s in statuses.items()}
    (out / "ash_aggregated_results.json").write_text(json.dumps({"scanner_results": results}))
    return out


def test_complete_scan_passes(tmp_path: Path) -> None:
    out = make_output(tmp_path, {"bandit": "PASSED", "grype": "FAILED"})
    assert check(out, frozenset()) == []  # FAILED = findings, reported by ASH's own exit code


def test_missing_output_dir_fails(tmp_path: Path) -> None:
    assert main([str(tmp_path / "nope")]) == 1


def test_missing_sarif_fails(tmp_path: Path) -> None:
    out = make_output(tmp_path, {"bandit": "PASSED"}, sarif=False)
    assert any("did not run" in p for p in check(out, frozenset()))


@pytest.mark.parametrize("status", ["MISSING", "ERROR", "SKIPPED"])
def test_scanner_that_did_not_run_fails(tmp_path: Path, status: str) -> None:
    out = make_output(tmp_path, {"bandit": "PASSED", "checkov": status})
    assert check(out, frozenset()) == [f"scanner checkov did not run (status {status})"]


def test_allowed_missing_scanner_passes(tmp_path: Path) -> None:
    out = make_output(tmp_path, {"bandit": "PASSED", "cdk-nag": "MISSING"})
    assert main([str(out), "--allow-missing", "cdk-nag,cfn-nag"]) == 0


def test_no_scanner_results_fails(tmp_path: Path) -> None:
    out = make_output(tmp_path, {})
    assert "no scanner results recorded" in check(out, frozenset())
