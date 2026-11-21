"""The helpers that let repo-backed tests follow the pinned versions."""

from __future__ import annotations

import pytest

from tests.versions import CATALOG, expected_commit, github_sources, newer, older, revision, tag, upstream


@pytest.mark.parametrize(
    ("version", "part", "by", "result"),
    [
        ("3.4.7-r1", "patch", 3, "3.4.10-r0"),
        ("1.16.0-r0", "minor", 1, "1.17.0-r0"),
        ("1.15.5", "patch", 2, "1.15.7"),
        ("1.15.5", "major", 1, "2.0.0"),
        ("20261201", "patch", 1, "20261201.0.1"),
    ],
)
def test_newer(version: str, part: str, by: int, result: str) -> None:
    assert newer(version, part, by) == result


@pytest.mark.parametrize(
    ("version", "result"),
    [("3.4.7-r1", "3.4.7-r0"), ("3.4.8-r0", "3.4.7-r0"), ("1.16.0-r0", "1.15.99-r0"), ("0.3.0", "0.2.99")],
)
def test_older(version: str, result: str) -> None:
    assert older(version) == result


@pytest.mark.parametrize("version", ["0.0.0-r0", "latest", "1.2.3-rc1", ""])
def test_bad_or_bottom_versions_are_refused(version: str) -> None:
    with pytest.raises(ValueError, match=r"older than|not a version"):
        older(version)


def test_repo_versions_are_read_from_the_catalog_and_recipes() -> None:
    for name in CATALOG.images:
        assert tag(name) == f"{upstream(name)}-r{revision(name)}"
    assert set(github_sources()) == {"spiffe/spire", "spiffe/spire-controller-manager", "spiffe/spiffe-csi"}
    assert github_sources()["spiffe/spire"] == upstream("spire-server")
    assert len(expected_commit("melange/spiffe-csi-driver.yaml")) == 40
