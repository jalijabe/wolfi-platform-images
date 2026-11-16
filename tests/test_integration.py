"""Image factory integration test, against a staged build (`task images:test`).

`task images:stage` builds every image from the recipes (network: Wolfi
packages, the grype database, upstream source), publishes it to a local
staging registry signed with a throwaway key, and writes release.json;
`task images:functest` runs the functional tests against those digests. This
module then verifies the result the way a consumer would: by tag, with the
staging key; another key and an unsigned image are refused; reuse works; and
promote copies exactly the tested digests to a fresh registry, refusing
anything untested.

Runs only with FACTORY_INTEGRATION=1, FACTORY_RELEASE, FACTORY_KEY and
FUNCTIONAL_REPORT set (the Taskfile sets them).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from imagefactory.factory import RELEASE_API, main

pytestmark = pytest.mark.skipif(
    os.environ.get("FACTORY_INTEGRATION") != "1", reason="set FACTORY_INTEGRATION=1 (task images:test)"
)

REPO = Path(__file__).resolve().parents[1]
BIN = os.environ.get("FACTORY_BIN", str(REPO / ".bin"))


def tool(name: str) -> str:
    return str(Path(BIN) / name)


@pytest.fixture(scope="module")
def release() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(Path(os.environ["FACTORY_RELEASE"]).read_text())
    return data


@pytest.fixture(scope="module")
def published(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {i["name"]: i for i in release["images"]}


@pytest.fixture(scope="module")
def staging(release: dict[str, Any]) -> str:
    ref: str = release["images"][0]["references"][0]
    return ref.split("/", 1)[0]


@pytest.fixture(scope="module")
def key() -> Path:
    return Path(os.environ["FACTORY_KEY"])


@pytest.fixture(scope="module")
def other_key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("other")
    subprocess.run([tool("cosign"), "generate-key-pair"], cwd=d, check=True, capture_output=True,
                   env={**os.environ, "COSIGN_PASSWORD": ""})  # fmt: skip
    return d / "cosign.key"


@pytest.fixture
def registry() -> Iterator[str]:
    """A fresh, empty registry on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        [tool("crane"), "registry", "serve", "--address", f"127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        with socket.socket() as c:
            if c.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.1)
    yield f"localhost:{port}"
    proc.terminate()
    proc.wait(timeout=10)


def cosign(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([tool("cosign"), *args], capture_output=True, text=True, check=False)


def factory(*args: str) -> int:
    os.environ["COSIGN_PASSWORD"] = ""
    try:
        return main([args[0], "--root", str(REPO), "--bin", BIN, *args[1:]])
    except SystemExit as e:  # the factory stops with the reason (gate, smoke, config)
        pytest.fail(f"factory stopped: {e}")


def test_every_image_passed_smoke_and_gate(published: dict[str, dict[str, Any]]) -> None:
    assert published
    for name, image in published.items():
        assert not image["reused"], name
        assert not image["smoke"].startswith("skipped"), name
        for plat, g in image["gate"]["platforms"].items():
            assert g["blocking"] == [], (name, plat)
        assert set(image["sboms"]) == set(image["platforms"]), name


def test_release_manifest(release: dict[str, Any]) -> None:
    assert release["apiVersion"] == RELEASE_API
    assert release["signing"] == {"mode": "key"}
    assert release["source"]["commit"]


def test_staged_images_verify_with_the_staging_key(
    published: dict[str, dict[str, Any]], staging: str, key: Path
) -> None:
    pub = str(key.with_suffix(".pub"))
    for name, image in published.items():
        ref = f"{staging}/{name}:{image['tag']}"  # by tag, as a consumer pulls
        r = cosign("verify", "--key", pub, "--insecure-ignore-tlog=true", ref)
        assert r.returncode == 0, (name, r.stderr)
        for plat, digest in image["platforms"].items():
            att = ("verify-attestation", "--key", pub, "--insecure-ignore-tlog=true", "--type", "spdxjson")
            r = cosign(*att, f"{staging}/{name}@{digest}")
            assert r.returncode == 0, (name, plat, r.stderr)


def test_another_key_does_not_verify(
    published: dict[str, dict[str, Any]], staging: str, other_key: Path
) -> None:
    name, image = next(iter(published.items()))
    r = cosign("verify", "--key", str(other_key.with_suffix(".pub")), "--insecure-ignore-tlog=true",
               f"{staging}/{name}:{image['tag']}")  # fmt: skip
    assert r.returncode != 0


def test_unsigned_image_does_not_verify(
    published: dict[str, dict[str, Any]], staging: str, key: Path, registry: str
) -> None:
    name, image = next(iter(published.items()))
    unsigned = f"{registry}/fixtures/unsigned:1"
    subprocess.run([tool("crane"), "copy", f"{staging}/{name}:{image['tag']}", unsigned],
                   check=True, capture_output=True)  # fmt: skip
    r = cosign("verify", "--key", str(key.with_suffix(".pub")), "--insecure-ignore-tlog=true", unsigned)
    assert r.returncode != 0


def test_reuse_from_skips_images_already_published_and_signed(
    published: dict[str, dict[str, Any]],
    staging: str,
    key: Path,
    other_key: Path,
    tmp_path: Path,
    registry: str,
) -> None:
    common = ["--key", str(other_key), "--target", registry, "--only", "haproxy", "--reuse-from", staging]
    # Signed by the staging key at staging: reused, not rebuilt.
    assert factory("build", "--out", str(tmp_path / "a"), *common, "--reuse-key", str(key)) == 0
    (img,) = json.loads((tmp_path / "a" / "release.json").read_text())["images"]
    assert img["reused"]
    assert img["digest"] == published["haproxy"]["digest"]
    # Checked against a key that did not sign it: rebuilt.
    assert factory("build", "--out", str(tmp_path / "b"), *common, "--reuse-key", str(other_key)) == 0
    (img,) = json.loads((tmp_path / "b" / "release.json").read_text())["images"]
    assert not img["reused"]


def test_promote_publishes_exactly_the_tested_digests(
    published: dict[str, dict[str, Any]], other_key: Path, tmp_path: Path, registry: str
) -> None:
    assert factory("promote", "--release", os.environ["FACTORY_RELEASE"],
                   "--functional", os.environ["FUNCTIONAL_REPORT"], "--out", str(tmp_path),
                   "--key", str(other_key), "--target", registry) == 0  # fmt: skip
    promoted = {i["name"]: i for i in json.loads((tmp_path / "release.json").read_text())["images"]}
    assert set(promoted) == set(published)
    for name, image in promoted.items():
        assert image["functional"]["ok"], name
        ref = f"{registry}/{name}:{image['tag']}"
        digest = subprocess.run([tool("crane"), "digest", ref], capture_output=True, text=True).stdout.strip()
        assert digest == published[name]["digest"], name  # what was tested is what was published
        r = cosign("verify", "--key", str(other_key.with_suffix(".pub")), "--insecure-ignore-tlog=true", ref)
        assert r.returncode == 0, (name, r.stderr)


def test_promote_refuses_when_functional_tests_failed(tmp_path: Path, registry: str) -> None:
    report = json.loads(Path(os.environ["FUNCTIONAL_REPORT"]).read_text())
    victim = next(iter(report["images"]))
    report["images"][victim]["failed"] = ["tests/functional/test_x.py::test_broken"]
    bad = tmp_path / "functional.json"
    bad.write_text(json.dumps(report))
    with pytest.raises(SystemExit, match="refusing to promote"):
        main(["promote", "--root", str(REPO), "--bin", BIN, "--release", os.environ["FACTORY_RELEASE"],
              "--functional", str(bad), "--out", str(tmp_path / "out"), "--keyless",
              "--target", registry])  # fmt: skip
    listing = subprocess.run([tool("crane"), "catalog", registry], capture_output=True, text=True).stdout
    assert listing.strip() == ""  # nothing was copied
