"""Propose updates: newer Wolfi packages and upstream source releases, each past
the 14-day cooldown.

- **Wolfi packages.** Every package pinned in an apko recipe (``name=version``)
  is compared with the newest build of that package in Wolfi's index that is
  at least 14 days old. When the image's main package moves, its tag and
  version annotation move with it.
- **Source builds.** Every melange recipe's upstream (its ``git-checkout``
  repository) is compared with the newest GitHub release at least 14 days old
  (no drafts or prereleases). An update sets the version, resets the epoch,
  pins ``expected-commit`` to the release tag's commit, and moves the tag, the
  apko pins of the built packages and the annotations of every image that
  installs them.

``plan`` lists what would change; ``apply`` edits the files in place, keeping
their comments and layout. Re-locking the Wolfi-only recipes (``task
images:lock``), the build, the CVE gate and the functional tests then decide
whether the update is good: the update workflow opens a pull request and runs
CI on it, and nothing is published unless all of that passes.

Usage: python -m imagefactory.update [--apply] [--summary out.md]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from imagefactory.factory import Catalog, _pins, load_catalog
from imagefactory.status import COOLDOWN, WOLFI_INDEX, github_upstream, http_get, parse_apkindex, version_key

Fetch = Callable[[str], bytes]


@dataclass(frozen=True)
class Change:
    kind: str  # "wolfi" or "source"
    file: str  # the recipe edited (apko for wolfi, melange for source)
    package: str
    old: str
    new: str
    released: str  # date the new version was built or released
    images: tuple[str, ...]  # images whose tag moves with this change
    commit: str = ""  # source builds: the release tag's commit
    source: str = ""  # source builds: owner/repo


# ---------------------------------------------------------------- detect


def _recipes(catalog: Catalog) -> dict[str, list[str]]:
    """apko recipe -> the images built from it."""
    out: dict[str, list[str]] = {}
    for name, meta in catalog.images.items():
        out.setdefault(meta["recipe"], []).append(name)
    return out


def wolfi_updates(
    root: Path, catalog: Catalog, index: dict[str, list[tuple[str, int]]], now: dt.datetime
) -> list[Change]:
    cutoff = (now - COOLDOWN).timestamp()
    changes = []
    for recipe, images in sorted(_recipes(catalog).items()):
        cfg = yaml.safe_load((root / recipe).read_text())
        for pkg, ver in _pins(cfg).items():
            if pkg.endswith("-src") or not ver:
                continue  # our own source-built packages follow their upstream release
            builds = [(v, t) for v, t in index.get(pkg, []) if t <= cutoff]
            if not builds:
                continue
            latest, built = max(builds, key=lambda b: version_key(b[0]))
            if version_key(latest) <= version_key(ver):
                continue
            moves = tuple(i for i in images if str(catalog.images[i]["tag"]) == ver)
            date = dt.datetime.fromtimestamp(built, dt.UTC).date().isoformat()
            changes.append(Change("wolfi", recipe, pkg, ver, latest, date, moves))
    return changes


def _checkout(melange: dict[str, Any]) -> dict[str, Any]:
    step = next(s for s in melange.get("pipeline", []) if s.get("uses") == "git-checkout")
    with_: dict[str, Any] = step["with"]
    return with_


def tag_commit(repo: str, tag: str, fetch: Fetch) -> str:
    """The commit a release tag points at (peeling annotated tags)."""
    ref = json.loads(fetch(f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}"))["object"]
    while ref["type"] == "tag":
        ref = json.loads(fetch(f"https://api.github.com/repos/{repo}/git/tags/{ref['sha']}"))["object"]
    sha: str = ref["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError(f"{repo}@{tag}: unexpected commit {sha!r}")
    return sha


def source_updates(root: Path, catalog: Catalog, fetch: Fetch, now: dt.datetime) -> list[Change]:
    by_package: dict[str, list[str]] = {}
    for name, meta in catalog.images.items():
        if "package" in meta:
            by_package.setdefault(meta["package"], []).append(name)
    changes = []
    for pkg_file, images in sorted(by_package.items()):
        m = yaml.safe_load((root / pkg_file).read_text())
        co = _checkout(m)
        repo = re.sub(r"^https://github\.com/|\.git$", "", str(co["repository"]))
        ours = str(m["package"]["version"])
        releases = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases?per_page=50"))
        up = github_upstream(repo, ours, releases, now)
        if up.current or up.latest is None:
            continue
        tag = str(co["tag"]).replace("${{package.version}}", up.latest)
        changes.append(
            Change(
                "source",
                pkg_file,
                str(m["package"]["name"]),
                ours,
                up.latest,
                up.latest_date or "",
                tuple(images),
                commit=tag_commit(repo, tag, fetch),
                source=repo,
            )
        )
    return changes


def plan(
    root: Path, catalog: Catalog, fetch: Fetch = http_get, now: dt.datetime | None = None
) -> list[Change]:
    now = now or dt.datetime.now(dt.UTC)
    index = parse_apkindex(fetch(WOLFI_INDEX))
    return wolfi_updates(root, catalog, index, now) + source_updates(root, catalog, fetch, now)


# ---------------------------------------------------------------- apply


def _sub_once(text: str, pattern: str, repl: str, where: str) -> str:
    new, n = re.subn(pattern, repl, text, count=1, flags=re.M)
    if n != 1:
        raise ValueError(f"{where}: expected exactly one match for {pattern!r}")
    return new


def _set_tag(images_yaml: str, image: str, old: str, new: str) -> str:
    """Change one image's `tag:` in images.yaml, keeping the file's layout."""
    block = re.search(rf"^  {re.escape(image)}:\n((?:    .*\n|\s*#.*\n|\n)*)", images_yaml, re.M)
    if block is None:
        raise ValueError(f"images.yaml: no entry for {image}")
    body = block.group(1)
    fixed = _sub_once(body, rf"^(    tag: ){re.escape(old)}$", rf"\g<1>{new}", f"images.yaml {image}")
    return images_yaml[: block.start(1)] + fixed + images_yaml[block.end(1) :]


def _set_pin(recipe_text: str, pkg: str, old: str, new: str, where: str) -> str:
    return _sub_once(
        recipe_text, rf"^(\s*-\s*){re.escape(pkg)}={re.escape(old)}$", rf"\g<1>{pkg}={new}", where
    )


def _set_annotation(recipe_text: str, old: str, new: str, where: str) -> str:
    return _sub_once(
        recipe_text, rf"^(\s*org\.opencontainers\.image\.version: ){re.escape(old)}$", rf"\g<1>{new}", where
    )


def apply(root: Path, catalog: Catalog, changes: Sequence[Change]) -> None:
    images_yaml = (root / "images.yaml").read_text()
    for c in changes:
        if c.kind == "wolfi":
            path = root / c.file
            text = _set_pin(path.read_text(), c.package, c.old, c.new, c.file)
            if c.images:  # the main package: the tag and annotation move with it
                text = _set_annotation(text, c.old, c.new, c.file)
                for image in c.images:
                    images_yaml = _set_tag(images_yaml, image, c.old, c.new)
            path.write_text(text)
            continue
        # A source build: version, epoch and commit in the melange recipe...
        mpath = root / c.file
        m = yaml.safe_load(mpath.read_text())
        old_full, new_full = f"{c.old}-r{m['package']['epoch']}", f"{c.new}-r0"
        names = [m["package"]["name"]] + [s["name"] for s in m.get("subpackages", [])]
        old_commit = str(_checkout(m)["expected-commit"]).replace(
            "${{vars.commit}}", str(m.get("vars", {}).get("commit", ""))
        )
        mtext = mpath.read_text()
        mtext = _sub_once(mtext, rf'^(  version: )"?{re.escape(c.old)}"?$', rf'\g<1>"{c.new}"', c.file)
        mtext = _sub_once(mtext, r"^(  epoch: )\d+$", r"\g<1>0", c.file)
        # Quoted: an all-digit SHA would otherwise be read as a number.
        mtext = _sub_once(
            mtext, rf'^(\s*(?:commit|expected-commit): )"?{old_commit}"?$', rf'\g<1>"{c.commit}"', c.file
        )
        mpath.write_text(mtext)
        # ...then the apko pins, annotation and tag of every image installing it.
        for image in c.images:
            recipe = catalog.images[image]["recipe"]
            rpath = root / recipe
            rtext = rpath.read_text()
            for name in names:
                if re.search(rf"^\s*-\s*{re.escape(name)}={re.escape(old_full)}$", rtext, re.M):
                    rtext = _set_pin(rtext, name, old_full, new_full, recipe)
            rtext = _set_annotation(rtext, old_full, new_full, recipe)
            rpath.write_text(rtext)
            images_yaml = _set_tag(images_yaml, image, old_full, new_full)
    (root / "images.yaml").write_text(images_yaml)


# ---------------------------------------------------------------- report


def summary(changes: Sequence[Change]) -> str:
    if not changes:
        return "No updates past the 14-day cooldown.\n"
    lines = [
        "Updates past the 14-day cooldown, found by the update workflow. CI on this pull request builds,",
        "CVE-gates and functionally tests every image; nothing is published unless all of it passes.",
        "",
        "| Kind | Recipe | Package | From | To | Released | Images |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in changes:
        to = c.new + (f" (`{c.commit[:12]}`)" if c.commit else "")
        imgs = ", ".join(c.images) if c.images else "—"
        lines.append(f"| {c.kind} | `{c.file}` | `{c.package}` | {c.old} | {to} | {c.released} | {imgs} |")
    if any(c.kind == "source" for c in changes):
        lines += [
            "",
            "Review for source builds (a bot cannot judge these):",
            "- the Go toolchain the new release needs (`go.mod`) against the recipe's `go-*` package;",
            "- `go/bump` entries: drop bumps the release already includes, never downgrade;",
            "- the upstream release notes for changes to flags, defaults or file layout the tests rely on.",
        ]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="imagefactory.update", description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--catalog", type=Path, default=Path("images.yaml"))
    ap.add_argument("--apply", action="store_true", help="edit the recipes, tags and pins in place")
    ap.add_argument("--summary", type=Path, help="write a Markdown summary (the pull request body)")
    ap.add_argument("--json", type=Path, help="write the changes as JSON")
    args = ap.parse_args(argv)
    root = args.root.resolve()
    catalog = load_catalog(args.catalog if args.catalog.is_absolute() else root / args.catalog)
    changes = plan(root, catalog)
    for c in changes:
        print(f"{c.kind:6} {c.file}: {c.package} {c.old} -> {c.new} ({c.released})")
    if not changes:
        print("no updates past the cooldown")
    if args.apply and changes:
        apply(root, catalog, changes)
    if args.summary:
        args.summary.write_text(summary(changes))
    if args.json:
        args.json.write_text(json.dumps([asdict(c) for c in changes], indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
