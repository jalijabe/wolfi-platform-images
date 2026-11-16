"""The update bot: newer Wolfi packages and upstream releases past the cooldown,
applied consistently across recipes, tags and pins. Offline: the Wolfi index
and GitHub are fakes; edits go to a copy of the repository's recipes."""

from __future__ import annotations

import datetime as dt
import io
import json
import shutil
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from imagefactory.factory import lint, load_catalog
from imagefactory.status import WOLFI_INDEX
from imagefactory.update import Change, apply, plan, summary, tag_commit

REPO = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 12, 20, tzinfo=dt.UTC)
OLD = int((NOW - dt.timedelta(days=20)).timestamp())  # past the cooldown
NEW = int((NOW - dt.timedelta(days=3)).timestamp())  # inside it
C1, C2 = "1" * 40, "2" * 40


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for d in ("apko", "melange"):
        shutil.copytree(REPO / d, tmp_path / d)
    shutil.copy(REPO / "images.yaml", tmp_path / "images.yaml")
    return tmp_path


def apkindex(*entries: tuple[str, str, int]) -> bytes:
    text = "\n\n".join(f"P:{p}\nV:{v}\nt:{t}" for p, v, t in entries) + "\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = text.encode()
        info = tarfile.TarInfo("APKINDEX")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def current_index() -> list[tuple[str, str, int]]:
    """Every package the recipes pin, at exactly the pinned version: no updates."""
    out = []
    for recipe in (REPO / "apko").glob("*.yaml"):
        for p in yaml.safe_load(recipe.read_text())["contents"]["packages"]:
            name, _, ver = str(p).partition("=")
            if not name.endswith("-src"):
                out.append((name, ver, OLD - 86400))
    return out


def gh_release(tag: str, days_ago: int, **kw: Any) -> dict[str, Any]:
    when = (NOW - dt.timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")
    return {"tag_name": tag, "published_at": when, "draft": False, "prerelease": False, **kw}


class Feed:
    def __init__(self, index: list[tuple[str, str, int]], releases: dict[str, list[dict[str, Any]]]) -> None:
        self.index, self.releases = index, releases
        self.refs: dict[str, dict[str, Any]] = {}

    def __call__(self, url: str) -> bytes:
        if url == WOLFI_INDEX:
            return apkindex(*self.index)
        if "/releases?" in url:
            repo = url.split("/repos/", 1)[1].split("/releases", 1)[0]
            return json.dumps(self.releases.get(repo, [])).encode()
        if "/git/" in url:
            return json.dumps({"object": self.refs[url]}).encode()
        raise AssertionError(url)


def unchanged_releases() -> dict[str, list[dict[str, Any]]]:
    return {
        "spiffe/spire": [gh_release("v1.15.5", 40)],
        "spiffe/spire-controller-manager": [gh_release("v0.8.1", 40)],
        "spiffe/spiffe-csi": [gh_release("v0.3.0", 40)],
    }


def test_nothing_newer_means_no_changes(repo: Path) -> None:
    assert (
        plan(repo, load_catalog(repo / "images.yaml"), Feed(current_index(), unchanged_releases()), NOW) == []
    )


def test_a_newer_main_package_moves_the_tag_and_annotation(repo: Path) -> None:
    feed = Feed([*current_index(), ("haproxy-3.4-nocaps", "3.4.10-r0", OLD)], unchanged_releases())
    cat = load_catalog(repo / "images.yaml")
    changes = plan(repo, cat, feed, NOW)
    assert [(c.kind, c.package, c.old, c.new, c.images) for c in changes] == [
        ("wolfi", "haproxy-3.4-nocaps", "3.4.7-r1", "3.4.10-r0", ("haproxy",))
    ]
    apply(repo, cat, changes)
    recipe = (repo / "apko/haproxy.yaml").read_text()
    assert "haproxy-3.4-nocaps=3.4.10-r0" in recipe
    assert "org.opencontainers.image.version: 3.4.10-r0" in recipe
    assert "# HAProxy from Wolfi packages." in recipe  # comments kept
    after = load_catalog(repo / "images.yaml")
    assert after.images["haproxy"]["tag"] == "3.4.10-r0"
    assert after.images["spire-server"]["tag"] == "1.15.5-r0"
    # Consistent except the lock, which `task images:lock` refreshes next.
    assert [p for p in lint(repo, after) if "is stale" not in p] == []


def test_a_newer_base_package_is_bumped_everywhere_without_moving_tags(repo: Path) -> None:
    feed = Feed([*current_index(), ("ca-certificates-bundle", "20261201-r0", OLD)], unchanged_releases())
    cat = load_catalog(repo / "images.yaml")
    changes = plan(repo, cat, feed, NOW)
    assert {c.file for c in changes} == {f"apko/{n}.yaml" for n in cat.images}
    assert all(c.images == () for c in changes)
    apply(repo, cat, changes)
    for n in cat.images:
        assert "ca-certificates-bundle=20261201-r0" in (repo / f"apko/{n}.yaml").read_text()
    assert {n: m["tag"] for n, m in load_catalog(repo / "images.yaml").images.items()} == {
        n: m["tag"] for n, m in cat.images.items()
    }


@pytest.mark.parametrize(
    "extra",
    [
        ("haproxy-3.4-nocaps", "3.4.10-r0", NEW),  # inside the cooldown
        ("haproxy-3.4-nocaps", "3.4.6-r0", OLD),  # older: never downgrade
        ("haproxy-3.2", "3.2.30-r0", OLD),  # another stream: not ours
    ],
)
def test_no_change_inside_the_cooldown_or_downward(repo: Path, extra: tuple[str, str, int]) -> None:
    feed = Feed([*current_index(), extra], unchanged_releases())
    assert plan(repo, load_catalog(repo / "images.yaml"), feed, NOW) == []


def test_a_newer_upstream_release_updates_the_source_build_and_every_image(repo: Path) -> None:
    rels = unchanged_releases()
    rels["spiffe/spire"] = [
        gh_release("v1.15.5", 40),
        gh_release("v1.15.7", 20),
        gh_release("v1.16.0", 5),  # inside the cooldown
        gh_release("v1.17.0-rc1", 20, prerelease=True),
    ]
    feed = Feed(current_index(), rels)
    base = "https://api.github.com/repos/spiffe/spire/git"
    feed.refs[f"{base}/ref/tags/v1.15.7"] = {"type": "tag", "sha": C2}  # annotated: peeled
    feed.refs[f"{base}/tags/{C2}"] = {"type": "commit", "sha": C1}
    cat = load_catalog(repo / "images.yaml")
    (change,) = plan(repo, cat, feed, NOW)
    assert (change.kind, change.package, change.old, change.new, change.commit) == (
        "source", "spire-server-src", "1.15.5", "1.15.7", C1,
    )  # fmt: skip
    assert change.images == ("spire-server", "spire-agent")
    apply(repo, cat, [change])
    m = yaml.safe_load((repo / "melange/spire.yaml").read_text())
    assert m["package"]["version"] == "1.15.7"
    assert m["package"]["epoch"] == 0
    assert m["vars"]["commit"] == C1  # a string, even though this SHA is all digits
    after = load_catalog(repo / "images.yaml")
    assert after.images["spire-server"]["tag"] == "1.15.7-r0"
    assert after.images["spire-agent"]["tag"] == "1.15.7-r0"
    assert "spire-agent-src=1.15.7-r0" in (repo / "apko/spire-agent.yaml").read_text()
    assert lint(repo, after) == []  # pins, tags, annotations and commit all agree


def test_tag_commit_refuses_a_bad_sha() -> None:
    def fetch(url: str) -> bytes:
        return json.dumps({"object": {"type": "commit", "sha": "nope"}}).encode()

    with pytest.raises(ValueError, match="unexpected commit"):
        tag_commit("o/r", "v1", fetch)


def test_summary_lists_changes_and_asks_for_source_review() -> None:
    change = Change("source", "melange/spire.yaml", "spire-server-src", "1.15.5", "1.15.7", "2026-11-30",
                    ("spire-server",), commit=C1, source="spiffe/spire")  # fmt: skip
    text = summary([change])
    assert "| source | `melange/spire.yaml` | `spire-server-src` | 1.15.5 | 1.15.7 (`111111111111`)" in text
    assert "go/bump" in text
    assert "nothing is published unless all of it passes" in text
    assert summary([]).startswith("No updates")
