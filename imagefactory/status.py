"""Status of the published images: fresh, secure, working.

Everything here is measured, never asserted:

- **Fresh**: when each published digest was built (the signed release manifest
  that first published it) and whether its main package is still current
  upstream: Wolfi's package index for Wolfi-only images, the upstream project's
  releases for source builds. A newer release counts only once it is past the
  same two-week cooldown the recipes follow.
- **Secure**: the published digest's signature verifies against the exact
  keyless identity, and a fresh grype scan applies the same CVE gate as the
  build (findings at or above the threshold, minus written exceptions).
- **Works**: the functional tests, run against the published digests.

``published`` resolves what is published now (a release-shaped JSON the
functional tests consume); ``status`` measures and writes status.json, which
statuspage renders.
"""

from __future__ import annotations

import ast
import datetime as dt
import io
import json
import os
import re
import tarfile
import tempfile
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from imagefactory.factory import (
    OCI_ARCH,
    RELEASE_API,
    SEVERITIES,
    Catalog,
    Runner,
    Signer,
    Tools,
    gate,
    load_exceptions,
)

STATUS_API = "wolfi-platform-images/status/v1"
COOLDOWN = dt.timedelta(days=14)
FRESH_DAYS = 30  # built within this many days counts as recently built
HISTORY_DAYS = 120
WOLFI_INDEX = "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz"

Fetch = Callable[[str], bytes]


def http_get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "wolfi-platform-images-status"})  # noqa: S310  # nosec B310 - https only, checked above
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310  # nosec B310 - https only, checked above
        data: bytes = r.read()
    return data


# ---------------------------------------------------------------- what is published


def published(catalog: Catalog, registry: str, run: Runner, tools: Tools) -> dict[str, Any]:
    """The images published now under each catalog tag, by digest, in the
    release-manifest shape the functional tests read. Missing tags are listed
    under ``missing``."""
    images, missing = [], []
    for name, meta in catalog.images.items():
        ref = f"{registry}/{name}:{meta['tag']}"
        r = run([tools("crane"), "digest", ref], capture_output=True, check=False)
        if r.returncode != 0:
            missing.append(name)
            continue
        digest = r.stdout.strip()
        platforms = {}
        for arch in catalog.archs:
            plat = f"linux/{OCI_ARCH[arch]}"
            platforms[plat] = run(
                [tools("crane"), "digest", "--platform", plat, ref], capture_output=True
            ).stdout.strip()
        images.append(
            {
                "name": name,
                "tag": str(meta["tag"]),
                "digest": digest,
                "platforms": platforms,
                "references": [f"{ref}@{digest}"],
                "reused": True,
            }
        )
    return {"apiVersion": RELEASE_API, "images": images, "missing": missing}


# ---------------------------------------------------------------- fresh


def build_times(releases: Sequence[dict[str, Any]]) -> dict[str, str]:
    """Digest -> when it was built: the earliest release manifest that built
    (did not reuse) it."""
    out: dict[str, str] = {}
    for rel in sorted(releases, key=lambda r: str(r.get("createdAt", ""))):
        for img in rel.get("images", []):
            if not img.get("reused") and img.get("digest") and img["digest"] not in out:
                out[img["digest"]] = rel["createdAt"]
    return out


def parse_apkindex(blob: bytes) -> dict[str, list[tuple[str, int]]]:
    """Package name -> [(version, build time)] from an APKINDEX.tar.gz."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        member = t.extractfile("APKINDEX")
        if member is None:
            raise ValueError("APKINDEX.tar.gz has no APKINDEX")
        text = member.read().decode()
    out: dict[str, list[tuple[str, int]]] = {}
    for block in text.split("\n\n"):
        fields = dict(line.split(":", 1) for line in block.splitlines() if len(line) > 2 and line[1] == ":")
        if "P" in fields and "V" in fields:
            out.setdefault(fields["P"], []).append((fields["V"], int(fields.get("t", "0") or 0)))
    return out


def _version_key(v: str) -> tuple[Any, ...]:
    """Order versions like 1.15.5, 3.4.7-r1, v0.8.1 (numeric parts numerically)."""
    parts = re.split(r"[.\-_+]", v.lstrip("v").replace("-r", ".r"))
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts)


@dataclass(frozen=True)
class Upstream:
    source: str  # "wolfi:<package>" or "github:<owner>/<repo>"
    ours: str
    latest: str | None
    latest_date: str | None
    current: bool
    note: str = ""


def wolfi_upstream(
    package: str, ours: str, index: dict[str, list[tuple[str, int]]], now: dt.datetime
) -> Upstream:
    cutoff = (now - COOLDOWN).timestamp()
    builds = [(v, t) for v, t in index.get(package, []) if t <= cutoff]
    if not builds:
        return Upstream(f"wolfi:{package}", ours, None, None, False, "not found in the Wolfi index")
    latest, built = max(builds, key=lambda b: _version_key(b[0]))
    date = dt.datetime.fromtimestamp(built, dt.UTC).date().isoformat()
    return Upstream(f"wolfi:{package}", ours, latest, date, _version_key(ours) >= _version_key(latest))


def github_upstream(repo: str, ours: str, releases: Sequence[dict[str, Any]], now: dt.datetime) -> Upstream:
    cutoff = now - COOLDOWN
    eligible = [
        r
        for r in releases
        if not r.get("draft")
        and not r.get("prerelease")
        and dt.datetime.fromisoformat(str(r["published_at"]).replace("Z", "+00:00")) <= cutoff
    ]
    if not eligible:
        return Upstream(f"github:{repo}", ours, None, None, False, "no release found")
    newest = max(eligible, key=lambda r: _version_key(str(r["tag_name"])))
    latest = str(newest["tag_name"]).lstrip("v")
    return Upstream(
        f"github:{repo}",
        ours,
        latest,
        str(newest["published_at"])[:10],
        _version_key(ours) >= _version_key(latest),
    )


def upstream_for(root: Path, meta: dict[str, Any]) -> tuple[str, str, str]:
    """(kind, what to look up, our version) for an image's main package."""
    if "package" in meta:
        m = yaml.safe_load((root / meta["package"]).read_text())
        repo = next(s["with"]["repository"] for s in m.get("pipeline", []) if s.get("uses") == "git-checkout")
        owner_repo = re.sub(r"^https://github.com/|\.git$", "", str(repo))
        return "github", owner_repo, str(m["package"]["version"])
    cfg = yaml.safe_load((root / meta["recipe"]).read_text())
    tag = str(meta["tag"])
    for p in cfg.get("contents", {}).get("packages", []):
        name, _, version = str(p).partition("=")
        if version == tag:
            return "wolfi", name, tag
    raise ValueError(f"{meta['recipe']}: no package pinned to the tag {tag}")


# ---------------------------------------------------------------- secure


def scan(
    ref: str, name: str, threshold: str, exceptions: Sequence[dict[str, Any]], run: Runner, tools: Tools
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "grype.json"
        run(
            [
                tools("grype"),
                f"registry:{ref}",
                "--platform",
                "linux/amd64",
                "-o",
                "json",
                "--file",
                str(report),
            ]
        )
        data = json.loads(report.read_text())
    counts = dict.fromkeys((*SEVERITIES, "unknown"), 0)
    for m in data.get("matches", []):
        sev = str(m["vulnerability"].get("severity", "Unknown")).lower()
        counts[sev if sev in counts else "unknown"] += 1
    g = gate(data, name, threshold, exceptions, dt.date.today())
    reasons = {(f.id, f.package): r for f, r in g.accepted}
    blocking = {(f.id, f.package) for f in g.blocking}
    order = {s: i for i, s in enumerate(reversed((*SEVERITIES, "unknown")))}
    found = []
    for m in data.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        key = (v["id"], a["name"])
        found.append(
            {
                "id": v["id"],
                "severity": str(v.get("severity", "Unknown")).lower(),
                "package": a["name"],
                "version": a["version"],
                "type": a.get("type", ""),
                "fixState": str(v.get("fix", {}).get("state", "unknown")),
                "fixedIn": list(v.get("fix", {}).get("versions", []) or []),
                "url": advisory_url(v["id"], str(v.get("dataSource", ""))),
                "blocking": key in blocking,
                "accepted": reasons.get(key),
            }
        )
    found.sort(key=lambda f: (order.get(f["severity"], 99), f["id"], f["package"]))
    return {
        "counts": counts,
        "total": g.total,
        "blocking": [f.id for f in g.blocking],
        "accepted": [{"id": f.id, "reason": r} for f, r in g.accepted],
        "findings": found,
        "dbBuilt": data.get("descriptor", {}).get("db", {}).get("status", {}).get("built")
        or data.get("descriptor", {}).get("db", {}).get("built"),
    }


def advisory_url(vid: str, data_source: str) -> str:
    """A human-readable advisory page for a vulnerability ID."""
    if vid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vid}"
    if vid.startswith("GO-"):
        return f"https://pkg.go.dev/vuln/{vid}"
    if vid.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vid}"
    return data_source if data_source.startswith("https://") else ""


# ---------------------------------------------------------------- what the tests check


def describe_tests(root: Path, results: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Functional-test results grouped by suite (test file), with each suite's
    and test's description taken from the docstrings in the test files."""
    outcome = {t: k for k in ("passed", "failed", "skipped") for t in results.get(k, [])}
    suites: dict[str, dict[str, Any]] = {}
    for nodeid in sorted(outcome):
        path, _, func = nodeid.partition("::")
        if path not in suites:
            summary, docs = _docstrings(root / path)
            suites[path] = {"file": path, "summary": summary, "tests": [], "_docs": docs}
        base = func.split("[", 1)[0]
        suites[path]["tests"].append(
            {
                "name": func,
                "title": _title(base),
                "doc": suites[path]["_docs"].get(base, ""),
                "outcome": outcome[nodeid],
            }
        )
    for suite in suites.values():
        del suite["_docs"]
    return list(suites.values())


ACRONYMS = {
    "id": "ID", "ids": "IDs", "spiffe": "SPIFFE", "svid": "SVID", "svids": "SVIDs", "csi": "CSI",
    "cve": "CVE", "cves": "CVEs", "ca": "CA", "haproxy": "HAProxy", "spire": "SPIRE", "http": "HTTP",
    "tls": "TLS", "api": "API",
}  # fmt: skip


def _title(func: str) -> str:
    """test_csi_driver_registers_with_the_kubelet -> CSI driver registers with the kubelet."""
    words = [ACRONYMS.get(w, w) for w in func.removeprefix("test_").split("_")]
    if words and words[0] == words[0].lower():
        words[0] = words[0].capitalize()
    return " ".join(words)


def _docstrings(path: Path) -> tuple[str, dict[str, str]]:
    """A test file's module docstring and its test functions' docstrings."""
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError):
        return "", {}
    # The first paragraph describes what the suite proves; the rest is how to run it.
    module = " ".join((ast.get_docstring(tree) or "").split("\n\n")[0].split())
    funcs = {
        n.name: " ".join((ast.get_docstring(n) or "").split())
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
    }
    return module, funcs


# ---------------------------------------------------------------- assemble


def measure(
    root: Path,
    catalog: Catalog,
    current: dict[str, Any],
    functional: dict[str, Any] | None,
    releases: Sequence[dict[str, Any]],
    previous: dict[str, Any] | None,
    run: Runner,
    tools: Tools,
    fetch: Fetch = http_get,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.UTC)
    exceptions = load_exceptions(root / "cve-exceptions.yaml")
    signer = Signer(catalog.identity, catalog.issuer)
    built_at = build_times(releases)
    wolfi_index: dict[str, list[tuple[str, int]]] | None = None
    images = []
    for img in current["images"]:
        name, digest = img["name"], img["digest"]
        meta = catalog.images[name]
        ref = img["references"][0].split(":" + img["tag"] + "@")[0] + "@" + digest
        verified = run(signer.verify(tools("cosign"), ref), capture_output=True, check=False).returncode == 0

        kind, what, ours = upstream_for(root, meta)
        if kind == "wolfi":
            if wolfi_index is None:
                wolfi_index = parse_apkindex(fetch(WOLFI_INDEX))
            up = wolfi_upstream(what, ours, wolfi_index, now)
        else:
            rels = json.loads(fetch(f"https://api.github.com/repos/{what}/releases?per_page=50"))
            up = github_upstream(what, ours, rels, now)

        built = built_at.get(digest)
        age = (now - dt.datetime.fromisoformat(built)).days if built else None
        f = (functional or {}).get("images", {}).get(name, {})
        passed, failed, skipped = (len(f.get(k, [])) for k in ("passed", "failed", "skipped"))
        images.append(
            {
                "name": name,
                "tag": img["tag"],
                "digest": digest,
                "reference": f"{ref.split('@')[0]}:{img['tag']}",
                "signature": "verified" if verified else "failed",
                "builtAt": built,
                "ageDays": age,
                "upstream": up.__dict__,
                "cves": scan(ref, name, catalog.max_cve_severity, exceptions, run, tools),
                "functional": {
                    "passed": passed,
                    "failed": failed,
                    "skipped": skipped,
                    "ok": passed > 0 and failed == 0 and skipped == 0,
                    "failures": f.get("failed", []),
                    "suites": describe_tests(root, f),
                },
            }
        )
    today = now.date().isoformat()
    entry = {
        "date": today,
        "images": {
            i["name"]: {"blocking": len(i["cves"]["blocking"]), "total": i["cves"]["total"]} for i in images
        },
    }
    history = [h for h in (previous or {}).get("history", []) if h.get("date") != today] + [entry]
    return {
        "apiVersion": STATUS_API,
        "generatedAt": now.isoformat(timespec="seconds"),
        "registry": catalog.registry,
        "signing": {"identity": catalog.identity, "issuer": catalog.issuer},
        "policy": {"maxCveSeverity": catalog.max_cve_severity, "freshDays": FRESH_DAYS, "cooldownDays": 14},
        "source": {
            "repository": f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{os.environ.get('GITHUB_REPOSITORY', 'local')}",
            "run": os.environ.get("GITHUB_RUN_ID", "local"),
        },
        "missing": current.get("missing", []),
        "images": images,
        "history": history[-HISTORY_DAYS:],
    }


def summary(status: dict[str, Any]) -> dict[str, Any]:
    """The three pillars, as the page and badges state them."""
    imgs = status["images"]
    ages = [i["ageDays"] for i in imgs if i["ageDays"] is not None]
    fresh_days = status["policy"]["freshDays"]
    return {
        "fresh": {
            "ok": bool(imgs)
            and len(ages) == len(imgs)
            and max(ages) <= fresh_days
            and all(i["upstream"]["current"] for i in imgs),
            "newest": min(ages) if ages else None,
            "oldest": max(ages) if ages else None,
            "current": sum(1 for i in imgs if i["upstream"]["current"]),
        },
        "secure": {
            "ok": bool(imgs)
            and all(not i["cves"]["blocking"] and i["signature"] == "verified" for i in imgs),
            "blocking": sum(len(i["cves"]["blocking"]) for i in imgs),
            "total": sum(i["cves"]["total"] for i in imgs),
            "signed": sum(1 for i in imgs if i["signature"] == "verified"),
        },
        "works": {
            "ok": bool(imgs) and all(i["functional"]["ok"] for i in imgs),
            "passed": sum(i["functional"]["passed"] for i in imgs),
            "failed": sum(i["functional"]["failed"] for i in imgs),
            "skipped": sum(i["functional"]["skipped"] for i in imgs),
        },
        "images": len(imgs),
        "missing": len(status.get("missing", [])),
    }


def read_releases(directory: Path | None) -> list[dict[str, Any]]:
    if directory is None or not directory.is_dir():
        return []
    out = []
    for p in sorted(directory.rglob("release.json")):
        data = json.loads(p.read_text())
        if data.get("apiVersion") == RELEASE_API:
            out.append(data)
    return out


# ---------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    from imagefactory.factory import _run, load_catalog
    from imagefactory.statuspage import write_site

    ap = argparse.ArgumentParser(prog="imagefactory.status", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_pub = sub.add_parser("published", help="resolve the published digests (input for the functional tests)")
    p_status = sub.add_parser("status", help="measure the published images and write the status site")
    for p in (p_pub, p_status):
        p.add_argument("--root", type=Path, default=Path.cwd())
        p.add_argument("--catalog", type=Path, default=Path("images.yaml"))
        p.add_argument("--bin", type=Path, default=Path(".bin"))
    p_pub.add_argument("--registry", help="default: the catalog's")
    p_pub.add_argument("--out", type=Path, required=True)
    p_status.add_argument("--current", type=Path, required=True, help="output of `published`")
    p_status.add_argument("--functional", type=Path, help="functional-test report for the published digests")
    p_status.add_argument(
        "--releases", type=Path, help="directory of release.json manifests (GitHub releases)"
    )
    p_status.add_argument("--previous", type=Path, help="the previous status.json, for history")
    p_status.add_argument("--site", type=Path, required=True)
    args = ap.parse_args(argv)

    root = args.root.resolve()
    catalog = load_catalog(args.catalog if args.catalog.is_absolute() else root / args.catalog)
    tools = Tools(args.bin.resolve())
    if args.cmd == "published":
        cur = published(catalog, (args.registry or catalog.registry).rstrip("/"), _run, tools)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(cur, indent=2) + "\n")
        print(f"published: {len(cur['images'])} images; missing: {', '.join(cur['missing']) or 'none'}")
        return 0

    def load(p: Path | None) -> dict[str, Any] | None:
        if p is None or not p.is_file():
            return None
        try:
            data: dict[str, Any] = json.loads(p.read_text())
        except json.JSONDecodeError:
            return None
        return data

    status = measure(
        root,
        catalog,
        json.loads(args.current.read_text()),
        load(args.functional),
        read_releases(args.releases),
        load(args.previous),
        _run,
        tools,
    )
    write_site(status, args.site)
    s = summary(status)
    print(json.dumps({k: s[k] for k in ("fresh", "secure", "works")}, indent=2))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
