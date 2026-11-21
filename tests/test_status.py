"""Status measurement and the status page: offline, with fake tools and feeds."""

from __future__ import annotations

import datetime as dt
import io
import json
import subprocess
import tarfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from imagefactory.factory import RELEASE_API, Catalog, Tools, load_catalog
from imagefactory.status import (
    build_times,
    github_upstream,
    measure,
    parse_apkindex,
    summary,
    upstream_for,
    wolfi_upstream,
)
from imagefactory.statuspage import badge, render, write_site
from tests.versions import tag, upstream

REPO = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 11, 16, 12, 0, tzinfo=dt.UTC)
DAY = 86400


def apkindex(*entries: tuple[str, str, int]) -> bytes:
    text = "\n\n".join(f"C:Q1x=\nP:{p}\nV:{v}\nt:{t}" for p, v, t in entries) + "\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = text.encode()
        info = tarfile.TarInfo("APKINDEX")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ---------------------------------------------------------------- fresh


def test_build_time_is_the_first_release_that_built_the_digest() -> None:
    releases = [
        {"createdAt": "2026-11-10T00:00:00+00:00", "images": [{"digest": "sha256:a", "reused": True}]},
        {"createdAt": "2026-11-01T00:00:00+00:00", "images": [{"digest": "sha256:a", "reused": False}]},
        {"createdAt": "2026-11-05T00:00:00+00:00", "images": [{"digest": "sha256:a", "reused": False}]},
    ]
    assert build_times(releases) == {"sha256:a": "2026-11-01T00:00:00+00:00"}


def test_apkindex_is_parsed() -> None:
    idx = parse_apkindex(
        apkindex(("haproxy-3.4-nocaps", "3.4.7-r1", 1), ("haproxy-3.4-nocaps", "3.4.8-r0", 2))
    )
    assert idx == {"haproxy-3.4-nocaps": [("3.4.7-r1", 1), ("3.4.8-r0", 2)]}


def test_wolfi_upstream_respects_the_cooldown() -> None:
    old = int((NOW - dt.timedelta(days=30)).timestamp())
    new = int((NOW - dt.timedelta(days=3)).timestamp())
    idx = parse_apkindex(apkindex(("h", "3.4.7-r1", old), ("h", "3.4.8-r0", new)))
    assert wolfi_upstream("h", "3.4.7-r1", idx, NOW).current  # 3.4.8 is inside the cooldown
    idx = parse_apkindex(apkindex(("h", "3.4.7-r1", old), ("h", "3.4.10-r0", old + DAY)))
    up = wolfi_upstream("h", "3.4.7-r1", idx, NOW)
    assert not up.current
    assert up.latest == "3.4.10-r0"  # numeric, not lexical, ordering
    assert not wolfi_upstream("gone", "1", idx, NOW).current


def release(tag: str, days_ago: int, **kw: Any) -> dict[str, Any]:
    when = (NOW - dt.timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")
    return {"tag_name": tag, "published_at": when, "draft": False, "prerelease": False, **kw}


def test_github_upstream_ignores_prereleases_drafts_and_the_cooldown() -> None:
    rels = [
        release("v1.15.5", 30),
        release("v1.16.0", 5),  # too new
        release("v1.17.0-rc1", 40, prerelease=True),
        release("v1.18.0", 40, draft=True),
    ]
    up = github_upstream("spiffe/spire", "1.15.5", rels, NOW)
    assert up.current
    assert up.latest == "1.15.5"
    up = github_upstream("spiffe/spire", "1.15.5", [*rels, release("v1.15.10", 20)], NOW)
    assert not up.current
    assert up.latest == "1.15.10"


def test_upstream_sources_come_from_the_recipes() -> None:
    c = load_catalog(REPO / "images.yaml")
    # The recipes and the catalog agree on each image's version.
    assert upstream_for(REPO, c.images["haproxy"]) == ("wolfi", "haproxy-3.4-nocaps", tag("haproxy"))
    for image, source in [("spire-server", "spiffe/spire"), ("spiffe-csi-driver", "spiffe/spiffe-csi")]:
        assert upstream_for(REPO, c.images[image]) == ("github", source, upstream(image))


# ---------------------------------------------------------------- measure


class FakeRunner:
    def __init__(self, matches: list[dict[str, Any]], verified: bool = True) -> None:
        self.matches = matches
        self.verified = verified

    def __call__(self, argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        tool, rc = Path(argv[0]).name, 0
        if tool == "grype":
            Path(argv[list(argv).index("--file") + 1]).write_text(json.dumps({"matches": self.matches}))
        if tool == "cosign" and argv[1] == "verify":
            rc = 0 if self.verified else 1
        return subprocess.CompletedProcess(list(argv), rc, "", "")


def match(vid: str, sev: str, pkg: str = "p") -> dict[str, Any]:
    return {"vulnerability": {"id": vid, "severity": sev}, "artifact": {"name": pkg, "version": "1"}}


def catalog() -> Catalog:
    c = load_catalog(REPO / "images.yaml")
    return Catalog(c.registry, "high", c.archs, c.identity, c.issuer, {"haproxy": c.images["haproxy"]})


def current() -> dict[str, Any]:
    ref = f"ghcr.io/o/r/haproxy:{tag('haproxy')}@sha256:abc"
    img = {"name": "haproxy", "tag": tag("haproxy"), "digest": "sha256:abc", "platforms": {}}
    return {"apiVersion": RELEASE_API, "images": [{**img, "references": [ref], "reused": True}],
            "missing": ["spire-server"]}  # fmt: skip


def fetch(url: str) -> bytes:
    assert "APKINDEX" in url
    return apkindex(("haproxy-3.4-nocaps", tag("haproxy"), int((NOW - dt.timedelta(days=40)).timestamp())))


def measured(matches: list[dict[str, Any]], verified: bool = True, **kw: Any) -> dict[str, Any]:
    functional = {"images": {"haproxy": {"passed": ["t::a", "t::b"], "failed": [], "skipped": []}}}
    releases = [
        {"createdAt": "2026-11-14T12:00:00+00:00", "images": [{"digest": "sha256:abc", "reused": False}]}
    ]
    runner, tools = FakeRunner(matches, verified), Tools(Path("/nonexistent"))
    func, prev = kw.get("functional", functional), kw.get("previous")
    return measure(REPO, catalog(), current(), func, releases, prev, runner, tools, fetch=fetch, now=NOW)


def test_a_healthy_image_passes_all_three_pillars() -> None:
    st = measured([match("CVE-1", "Medium"), match("CVE-2", "Low")])
    (img,) = st["images"]
    assert img["ageDays"] == 2
    assert img["upstream"]["current"]
    assert img["signature"] == "verified"
    assert img["cves"]["counts"]["medium"] == 1
    assert img["cves"]["blocking"] == []
    assert img["functional"]["ok"]
    s = summary(st)
    assert s["fresh"]["ok"]
    assert s["secure"]["ok"]
    assert s["works"]["ok"]
    assert st["missing"] == ["spire-server"]


@pytest.mark.parametrize(
    ("kw", "pillar"),
    [
        ({"matches": [match("CVE-9", "Critical")]}, "secure"),
        ({"matches": [], "verified": False}, "secure"),
        ({"matches": [], "functional": {"images": {"haproxy": {"passed": ["a"], "failed": ["b"]}}}}, "works"),
        ({"matches": [], "functional": None}, "works"),  # never tested is not working
    ],
)
def test_a_problem_fails_its_pillar(kw: dict[str, Any], pillar: str) -> None:
    matches = kw.pop("matches")
    verified = kw.pop("verified", True)
    s = summary(measured(matches, verified, **kw))
    assert not s[pillar]["ok"]


def test_an_exception_is_reported_but_does_not_block() -> None:
    st = measured([match("GHSA-mgcc-cww5-fp2q", "High", "github.com/go-jose/go-jose/v3")])
    # The exception is for spire-server, not haproxy: it blocks here.
    assert st["images"][0]["cves"]["blocking"] == ["GHSA-mgcc-cww5-fp2q"]


def test_history_keeps_one_entry_per_day() -> None:
    first = measured([match("CVE-1", "High")])
    again = measured([], previous=first)
    assert [h["date"] for h in again["history"]] == ["2026-11-16"]
    assert again["history"][0]["images"]["haproxy"] == {"blocking": 0, "total": 0}
    earlier = {"history": [{"date": "2026-11-15", "images": {"haproxy": {"blocking": 1, "total": 3}}}]}
    assert [h["date"] for h in measured([], previous=earlier)["history"]] == ["2026-11-15", "2026-11-16"]


# ---------------------------------------------------------------- page


def test_page_and_badges_render(tmp_path: Path) -> None:
    st = measured([match("CVE-1", "Medium")])
    write_site(st, tmp_path)
    page = (tmp_path / "index.html").read_text()
    assert "<title>Image Status</title>" in page
    for words in (
        "Recently built",
        "Secure",
        "Actually works",
        "haproxy",
        "2/2 passing",
        "Verify it yourself",
    ):
        assert words in page, words
    assert json.loads((tmp_path / "status.json").read_text())["apiVersion"]
    for name in ("haproxy-built.svg", "haproxy-cves.svg", "haproxy-tests.svg", "fresh.svg", "secure.svg"):
        assert (tmp_path / "badges" / name).read_text().startswith("<svg")


def test_page_escapes_untrusted_text() -> None:
    st = measured([])
    st["images"][0]["name"] = "<script>alert(1)</script>"
    assert "<script>alert(1)</script>" not in render(st)


def test_badge_text_colour_follows_the_fill() -> None:
    assert 'fill="#0b0b0b" font-weight' in badge("built", "40 days ago", "#fab219")
    assert 'fill="#ffffff" font-weight' in badge("tests", "7/7 passing", "#0ca30c")


# ---------------------------------------------------------------- drill-down


def test_findings_carry_detail_and_the_reason_an_accepted_one_is_accepted(tmp_path: Path) -> None:
    from imagefactory.status import scan

    matches = [
        {**match("GHSA-mgcc-cww5-fp2q", "High", "github.com/go-jose/go-jose/v3"),
         "vulnerability": {"id": "GHSA-mgcc-cww5-fp2q", "severity": "High", "fix": {"state": "not-fixed"}}},
        match("CVE-2", "Low", "zlib"),
        match("CVE-9", "Critical", "openssl"),
    ]  # fmt: skip
    exc = [{"image": "spire-server", "id": "GHSA-mgcc-cww5-fp2q", "package": "github.com/go-jose/go-jose/v3",
            "reason": "Not reachable: <bundleformat>", "owner": "x", "expires": "2099-01-01"}]  # fmt: skip
    out = scan("r@d", "spire-server", "high", exc, FakeRunner(matches), Tools(tmp_path))
    by_id = {f["id"]: f for f in out["findings"]}
    assert [f["id"] for f in out["findings"]] == [
        "CVE-9",
        "GHSA-mgcc-cww5-fp2q",
        "CVE-2",
    ]  # most severe first
    assert by_id["GHSA-mgcc-cww5-fp2q"]["accepted"] == "Not reachable: <bundleformat>"
    assert not by_id["GHSA-mgcc-cww5-fp2q"]["blocking"]
    assert by_id["GHSA-mgcc-cww5-fp2q"]["url"] == "https://github.com/advisories/GHSA-mgcc-cww5-fp2q"
    assert by_id["CVE-9"]["blocking"]
    assert by_id["CVE-9"]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-9"
    assert by_id["CVE-2"]["accepted"] is None


def test_functional_results_are_described_from_the_test_files() -> None:
    from imagefactory.status import describe_tests

    results = {
        "passed": ["tests/functional/test_haproxy.py::test_proxies_requests_to_a_healthy_backend"],
        "failed": ["tests/functional/test_spire.py::test_agent_attests_with_a_join_token"],
        "skipped": [],
    }
    suites = {s["file"]: s for s in describe_tests(REPO, results)}
    hap = suites["tests/functional/test_haproxy.py"]
    assert hap["summary"].startswith("HAProxy works")
    (t,) = hap["tests"]
    assert t == {**t, "title": "Proxies requests to a healthy backend", "outcome": "passed"}
    assert suites["tests/functional/test_spire.py"]["tests"][0]["outcome"] == "failed"
    assert (
        "task tools:functest" not in suites["tests/functional/test_spire.py"]["summary"]
    )  # first paragraph only


def test_test_titles_keep_acronyms() -> None:
    from imagefactory.status import _title

    assert _title("test_server_mints_svids_from_its_ca") == "Server mints SVIDs from its CA"
    assert _title("test_csi_driver_registers_with_the_kubelet") == "CSI driver registers with the kubelet"


def detailed_status() -> dict[str, Any]:
    st = measured([match("CVE-1", "Medium", "openssl")])
    img = st["images"][0]
    img["cves"]["findings"] = [
        {"id": "GHSA-x", "severity": "high", "package": "p", "version": "1", "type": "go-module",
         "fixState": "not-fixed", "fixedIn": [], "url": "https://github.com/advisories/GHSA-x",
         "blocking": False, "accepted": "Not reachable <here>"},
    ]  # fmt: skip
    img["functional"]["suites"] = [
        {"file": "tests/functional/test_haproxy.py", "summary": "HAProxy works.",
         "tests": [{"name": "test_a", "title": "A", "doc": "", "outcome": "passed"},
                   {"name": "test_b", "title": "B", "doc": "", "outcome": "failed"}]},
    ]  # fmt: skip
    return st


def test_pills_open_the_row_with_what_was_tested_and_the_findings() -> None:
    page = render(detailed_status())
    assert 'class="pill ok opener" data-row="d-haproxy" data-section="cves"' in page
    assert 'data-row="d-haproxy" data-section="tests"' in page
    assert '<tr class="detail" id="d-haproxy">' in page
    assert 'data-part="tests"' in page
    assert 'data-part="cves"' in page
    assert "Why it is accepted:</strong> Not reachable &lt;here&gt;" in page
    assert '<a href="https://github.com/advisories/GHSA-x"' in page
    assert "Failed: </span>" in page  # outcome in words, not colour alone


def test_pull_and_verify_commands_are_copyable() -> None:
    page = render(detailed_status())
    ref = f"ghcr.io/o/r/haproxy:{tag('haproxy')}@sha256:abc"
    assert f"docker pull {ref}</pre>" in page
    assert f"  {ref}</pre>" in page  # the image's own verify command
    assert page.count('class="copy"') == 3  # pull, verify, and the page's "verify it yourself" box
    assert "navigator.clipboard.writeText" in page
