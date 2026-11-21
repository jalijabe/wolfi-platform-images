"""The versions the repository pins today, for tests that run against the real
recipes and catalog. Such tests derive their expectations from these instead of
literals, so a routine version bump (`task update`) does not break them; tests
on synthetic data keep their literals."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from imagefactory.factory import load_catalog
from imagefactory.status import upstream_for

REPO = Path(__file__).resolve().parents[1]
CATALOG = load_catalog(REPO / "images.yaml")

_VERSION = re.compile(r"(\d+(?:\.\d+)*)(?:-r(\d+))?")
_PARTS = {"major": 0, "minor": 1, "patch": 2}


def tag(image: str) -> str:
    """The catalog tag, e.g. 3.4.7-r1."""
    return str(CATALOG.images[image]["tag"])


def upstream(image: str) -> str:
    """The tag without its Wolfi revision, e.g. 3.4.7."""
    return _split(tag(image))[0]


def revision(image: str) -> int:
    rev = _split(tag(image))[1]
    assert rev is not None, f"{image}: tag {tag(image)} has no revision"
    return rev


def expected_commit(recipe: str) -> str:
    """The full commit a melange recipe's git-checkout expects."""
    m = yaml.safe_load((REPO / recipe).read_text())
    return next(
        str(s["with"]["expected-commit"]) for s in m.get("pipeline", []) if s.get("uses") == "git-checkout"
    )


def github_sources() -> dict[str, str]:
    """owner/repo -> pinned upstream version, for every source-built image."""
    out = {}
    for meta in CATALOG.images.values():
        kind, what, version = upstream_for(REPO, meta)
        if kind == "github":
            out[what] = version
    return out


def newer(version: str, part: str = "patch", by: int = 1) -> str:
    """`version` with `part` raised by `by` and the parts below it reset;
    a Wolfi revision, if present, becomes -r0 (1.15.5-r2 -> 1.15.6-r0)."""
    nums, rev = _split(version)
    parts = [int(n) for n in nums.split(".")]
    i = _PARTS[part]
    parts += [0] * (i + 1 - len(parts))
    parts[i] += by
    parts[i + 1 :] = [0] * (len(parts) - i - 1)
    return _join(parts, None if rev is None else 0)


def older(version: str) -> str:
    """A version just below `version`: the revision, else the last nonzero part, steps down."""
    nums, rev = _split(version)
    parts = [int(n) for n in nums.split(".")]
    if rev:
        return _join(parts, rev - 1)
    for i in reversed(range(len(parts))):
        if parts[i]:
            parts[i] -= 1
            parts[i + 1 :] = [99] * (len(parts) - i - 1)
            return _join(parts, rev)
    raise ValueError(f"nothing is older than {version}")


def _split(version: str) -> tuple[str, int | None]:
    m = _VERSION.fullmatch(version)
    if not m:
        raise ValueError(f"not a version: {version!r}")
    return m[1], None if m[2] is None else int(m[2])


def _join(parts: list[int], rev: int | None) -> str:
    return ".".join(map(str, parts)) + ("" if rev is None else f"-r{rev}")
