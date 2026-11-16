"""Image factory integration test.

Builds real images from the recipes (network: Wolfi packages, the grype
database, upstream source), publishes them to a local registry with a
throwaway cosign key, and verifies the result the way a consumer would:
by tag, with the factory key; another key and an unsigned image are refused.
A second run with --skip-existing reuses what is already published.

Runs only with FACTORY_INTEGRATION=1 (`task images:test`); FACTORY_DOCKER=1
adds the melange source builds, which need Docker.
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
WOLFI_ONLY = ["haproxy"]
SOURCE_BUILT = ["spire-server", "spire-agent", "spire-controller-manager", "spiffe-csi-driver"]


def tool(name: str) -> str:
    return str(Path(os.environ.get("FACTORY_BIN", REPO / ".bin")) / name)


@pytest.fixture(scope="module")
def target() -> Iterator[str]:
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


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    out = {}
    for name in ("factory", "other"):
        d = tmp_path_factory.mktemp(name)
        subprocess.run(
            [tool("cosign"), "generate-key-pair"],
            cwd=d,
            check=True,
            capture_output=True,
            env={**os.environ, "COSIGN_PASSWORD": ""},
        )
        out[name] = d / "cosign.key"
    return out


def build(target: str, key: Path, out: Path, *extra: str) -> dict[str, Any]:
    images = WOLFI_ONLY + (SOURCE_BUILT if os.environ.get("FACTORY_DOCKER") == "1" else [])
    os.environ["COSIGN_PASSWORD"] = ""
    args = [
        "build",
        "--root", str(REPO),
        "--out", str(out),
        "--bin", os.environ.get("FACTORY_BIN", str(REPO / ".bin")),
        "--arch", "x86_64,aarch64",
        "--key", str(key),
        "--target", target,
        *extra,
    ]  # fmt: skip
    for name in images:
        args += ["--only", name]
    try:
        rc = main(args)
    except SystemExit as e:  # the factory stops with the reason (gate, smoke, config)
        pytest.fail(f"factory stopped: {e}")
    assert rc == 0
    release: dict[str, Any] = json.loads((out / "release.json").read_text())
    return release


@pytest.fixture(scope="module")
def release(target: str, keys: dict[str, Path], tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return build(target, keys["factory"], tmp_path_factory.mktemp("factory"))


@pytest.fixture(scope="module")
def published(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {i["name"]: i for i in release["images"]}


def cosign(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([tool("cosign"), *args], capture_output=True, text=True, check=False)


def test_every_image_passed_smoke_and_gate(published: dict[str, dict[str, Any]]) -> None:
    for name, image in published.items():
        assert not image["reused"], name
        assert not image["smoke"].startswith("skipped"), name
        for plat, g in image["gate"]["platforms"].items():
            assert g["blocking"] == [], (name, plat)


def test_release_manifest(release: dict[str, Any]) -> None:
    assert release["apiVersion"] == RELEASE_API
    assert release["signing"] == {"mode": "key"}
    assert release["source"]["commit"]


def test_published_images_verify_with_the_factory_key(
    published: dict[str, dict[str, Any]],
    target: str,
    keys: dict[str, Path],
) -> None:
    pub = str(keys["factory"].with_suffix(".pub"))
    for name, image in published.items():
        ref = f"{target}/{name}:{image['tag']}"  # by tag, as a consumer pulls
        r = cosign("verify", "--key", pub, "--insecure-ignore-tlog=true", ref)
        assert r.returncode == 0, (name, r.stderr)
        assert image["platforms"], name
        for plat, digest in image["platforms"].items():
            r = cosign(
                "verify-attestation", "--key", pub, "--insecure-ignore-tlog=true", "--type", "spdxjson",
                f"{target}/{name}@{digest}",
            )  # fmt: skip
            assert r.returncode == 0, (name, plat, r.stderr)


def test_another_key_does_not_verify(
    published: dict[str, dict[str, Any]],
    target: str,
    keys: dict[str, Path],
) -> None:
    name, image = next(iter(published.items()))
    r = cosign("verify", "--key", str(keys["other"].with_suffix(".pub")), "--insecure-ignore-tlog=true",
               f"{target}/{name}:{image['tag']}")  # fmt: skip
    assert r.returncode != 0


def test_unsigned_image_does_not_verify(
    published: dict[str, dict[str, Any]],
    target: str,
    keys: dict[str, Path],
) -> None:
    name, image = next(iter(published.items()))
    unsigned = f"{target}/fixtures/unsigned:1"
    subprocess.run([tool("crane"), "mutate", f"{target}/{name}:{image['tag']}", "--label", "fixture=unsigned",
                    "-t", unsigned], check=True, capture_output=True)  # fmt: skip
    r = cosign(
        "verify", "--key", str(keys["factory"].with_suffix(".pub")), "--insecure-ignore-tlog=true", unsigned
    )
    assert r.returncode != 0


def test_skip_existing_reuses_published_images(
    published: dict[str, dict[str, Any]],
    target: str,
    keys: dict[str, Path],
    tmp_path: Path,
) -> None:
    again = build(target, keys["factory"], tmp_path, "--skip-existing")
    for image in again["images"]:
        assert image["reused"], image["name"]
        assert image["digest"] == published[image["name"]]["digest"]


def test_skip_existing_rebuilds_when_signed_by_another_key(
    published: dict[str, dict[str, Any]],
    target: str,
    keys: dict[str, Path],
    tmp_path: Path,
) -> None:
    # Only the Wolfi-only image: rebuilding the source builds would double the run.
    images = [i for i in published if i in WOLFI_ONLY]
    os.environ["COSIGN_PASSWORD"] = ""
    args = [
        "build",
        "--root", str(REPO),
        "--out", str(tmp_path),
        "--bin", os.environ.get("FACTORY_BIN", str(REPO / ".bin")),
        "--arch", "x86_64",
        "--key", str(keys["other"]),
        "--target", target,
        "--skip-existing",
    ]  # fmt: skip
    for name in images:
        args += ["--only", name]
    assert main(args) == 0
    for image in json.loads((tmp_path / "release.json").read_text())["images"]:
        assert not image["reused"], image["name"]
