"""The SARIF sent to code scanning keeps exactly what ASH counts as actionable."""

from __future__ import annotations

import json
from pathlib import Path

from imagefactory.sariffilter import filter_sarif, main


def sarif(*results: dict[str, object]) -> dict[str, object]:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ASH"}}, "results": list(results)}]}


SUPPRESSED = {"ruleId": "S", "level": "error", "suppressions": [{"kind": "inSource", "justification": "pin"}]}
NOTE = {"ruleId": "B101", "level": "note"}
ERROR = {"ruleId": "CKV_K8S_16", "level": "error"}
WARNING = {"ruleId": "B310", "level": "warning"}


def test_keeps_unsuppressed_errors_and_warnings_only() -> None:
    out, kept, dropped = filter_sarif(sarif(SUPPRESSED, NOTE, ERROR, WARNING))
    assert out["runs"][0]["results"] == [ERROR, WARNING]
    assert (kept, dropped) == (2, 2)
    assert out["runs"][0]["tool"] == {"driver": {"name": "ASH"}}


def test_a_new_unsuppressed_finding_is_never_dropped() -> None:
    out, kept, _ = filter_sarif(sarif({"ruleId": "NEW", "level": "error"}))
    assert kept == 1
    assert out["runs"][0]["results"][0]["ruleId"] == "NEW"


def test_cli(tmp_path: Path) -> None:
    src, dst = tmp_path / "in.sarif", tmp_path / "out.sarif"
    src.write_text(json.dumps(sarif(SUPPRESSED, ERROR)))
    assert main([str(src), str(dst)]) == 0
    assert json.loads(dst.read_text())["runs"][0]["results"] == [ERROR]
    assert main([]) == 2
