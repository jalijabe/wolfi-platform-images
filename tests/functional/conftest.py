"""Functional tests: run the built images and prove they do their job.

The suite runs against the exact digests in a release manifest
(FACTORY_RELEASE, written by `imagefactory build`), so what is tested is what
`imagefactory promote` publishes. Every test is marked with the image(s) it
exercises (``@pytest.mark.image(...)``); the per-image results are written to
FUNCTIONAL_REPORT, which promote requires: at least one pass, no failures and
no skips for every newly built image.

Tests run the images the hardened way: read-only root filesystem, every
capability dropped and no-new-privileges, unless the image's job needs more
(the CSI node plugin runs privileged, as on any cluster).
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.functional.helpers import docker, run, tool

RELEASE = os.environ.get("FACTORY_RELEASE")
REPORT = os.environ.get("FUNCTIONAL_REPORT")
LOCAL_PREFIX = "functest.local"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    here = Path(__file__).parent
    mine = [i for i in items if here in Path(str(i.path)).parents]
    if not RELEASE:
        for item in mine:
            item.add_marker(pytest.mark.skip(reason="set FACTORY_RELEASE (task images:functest)"))
        return
    # A partial build (ONLY=...) cannot run tests that need other images; they
    # are skipped, and a skip never counts as passing for promote.
    present = {i["name"] for i in json.loads(Path(RELEASE).read_text())["images"]}
    for item in mine:
        marker = item.get_closest_marker("image")
        missing = set(marker.args) - present if marker else set()
        if missing:
            item.add_marker(pytest.mark.skip(reason=f"not in this release: {', '.join(sorted(missing))}"))


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "image(*names): the images a functional test exercises")
    config.stash[_RESULTS] = {}


_RESULTS = pytest.StashKey[dict[str, dict[str, str]]]()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Generator[None, Any, None]:
    outcome = yield
    rep = outcome.get_result()
    marker = item.get_closest_marker("image")
    if marker is None:
        return
    results = item.config.stash[_RESULTS]
    for name in marker.args:
        per_image = results.setdefault(name, {})
        prev = per_image.get(item.nodeid)
        # A failure in any phase wins; a skip in setup counts as a skip.
        if rep.failed:
            per_image[item.nodeid] = "failed"
        elif rep.skipped and prev != "failed":
            per_image[item.nodeid] = "skipped"
        elif rep.when == "call" and rep.passed and prev is None:
            per_image[item.nodeid] = "passed"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not REPORT:
        return
    images: dict[str, dict[str, list[str]]] = {}
    for name, tests in session.config.stash.get(_RESULTS, {}).items():
        images[name] = {
            k: sorted(t for t, o in tests.items() if o == k) for k in ("passed", "failed", "skipped")
        }
    Path(REPORT).write_text(json.dumps({"images": images}, indent=2) + "\n")


@pytest.fixture(scope="session")
def release() -> dict[str, Any]:
    assert RELEASE
    data: dict[str, Any] = json.loads(Path(RELEASE).read_text())
    return data


@pytest.fixture(scope="session")
def image(release: dict[str, Any], tmp_path_factory: pytest.TempPathFactory) -> Callable[[str], str]:
    """Fetch an image by the digest in the release (crane verifies it), load it
    into Docker and tag it functest.local/<name>:test; returns that reference.
    Loading from a tarball, rather than pulling, works whether or not the
    Docker daemon can reach the staging registry (e.g. Docker Desktop)."""
    by_name = {i["name"]: i for i in release["images"]}
    loaded: dict[str, str] = {}
    tmp = tmp_path_factory.mktemp("images")

    def get(name: str) -> str:
        if name not in loaded:
            assert name in by_name, f"{name} is not in the release under test"
            img = by_name[name]
            repo = img["references"][0].split("@", 1)[0].rsplit(":", 1)[0]
            tar = tmp / f"{name}.tar"
            run(tool("crane"), "pull", "--platform", "linux/amd64", f"{repo}@{img['digest']}", str(tar),
                timeout=600)  # fmt: skip
            out = docker("load", "-i", str(tar), timeout=600).stdout
            ref = out.strip().splitlines()[-1].split(": ", 1)[1].strip()
            local = f"{LOCAL_PREFIX}/{name}:test"
            docker("tag", ref, local)
            loaded[name] = local
        return loaded[name]

    return get


@pytest.fixture(scope="module")
def network() -> Iterator[str]:
    name = f"functest-{uuid.uuid4().hex[:8]}"
    docker("network", "create", name)
    yield name
    docker("network", "rm", name, check=False)


@pytest.fixture(scope="module")
def containers() -> Iterator[list[str]]:
    """Containers to remove when the module finishes (logs are printed on failure)."""
    started: list[str] = []
    yield started
    for c in started:
        docker("rm", "-f", c, check=False)
