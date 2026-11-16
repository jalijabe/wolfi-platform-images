"""Image factory: catalog, plan, CVE gate, recipe lint, signing, and the publish
order. Offline: external tools are replaced by a recording runner."""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from imagefactory.factory import (
    HOST_ARCH,
    RELEASE_API,
    Builder,
    Catalog,
    Factory,
    Job,
    Signer,
    Smoke,
    Tools,
    check_config,
    elf_interpreter,
    gate,
    lint,
    load_catalog,
    load_exceptions,
    lock_checksum,
    main,
    plan,
    release_manifest,
    smoke_argv,
)

REPO = Path(__file__).resolve().parents[1]
TODAY = dt.date(2026, 11, 15)
IDENTITY = "https://github.com/o/r/.github/workflows/publish.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


def repo_catalog() -> Catalog:
    return load_catalog(REPO / "images.yaml")


def catalog(**images: dict[str, Any]) -> Catalog:
    return Catalog(
        registry="ghcr.io/o/r",
        max_cve_severity="high",
        archs=("x86_64",),
        identity=IDENTITY,
        issuer=ISSUER,
        images=images
        or {
            "haproxy": {
                "tag": "3.4.7-r1",
                "recipe": "apko/haproxy.yaml",
                "smoke": {"args": ["-v"], "expect": "HAProxy version"},
            },
            "spire-server": {
                "tag": "1.15.5-r0",
                "recipe": "apko/spire-server.yaml",
                "package": "melange/spire.yaml",
            },
        },
    )


# ---------------------------------------------------------------- catalog


def test_repo_catalog_loads() -> None:
    c = repo_catalog()
    assert c.max_cve_severity == "high"
    assert c.identity.endswith("/.github/workflows/publish.yml@refs/heads/main")
    assert c.issuer == ISSUER
    assert {"haproxy", "spire-server", "spire-agent"} <= set(c.images)


def write_catalog(tmp_path: Path, **over: Any) -> Path:
    data = yaml.safe_load((REPO / "images.yaml").read_text())
    data.update(over)
    f = tmp_path / "images.yaml"
    f.write_text(yaml.safe_dump(data))
    return f


@pytest.mark.parametrize(
    ("over", "error"),
    [
        ({"maxCveSeverity": "severe"}, "maxCveSeverity must be one of"),
        ({"archs": ["riscv64"]}, "archs must be"),
        ({"signing": {"identity": "http://x", "issuer": "y"}}, "https identity"),
        ({"images": {"Bad_Name": {"tag": "1", "recipe": "apko/x.yaml"}}}, "lowercase"),
        ({"images": {"x": {"tag": "latest", "recipe": "apko/x.yaml"}}}, "is not a version"),
        ({"images": {"x": {"tag": "1", "recipe": "../x.yaml"}}}, "recipe must be"),
        ({"images": {"x": {"tag": "1", "recipe": "apko/x.yaml", "package": "x.yaml"}}}, "package must be"),
        ({"images": {"x": {"tag": "1", "recipe": "apko/x.yaml", "base": "y"}}}, "unknown keys base"),
        ({"images": {}}, "no images"),
    ],
)
def test_bad_catalogs_are_refused(tmp_path: Path, over: dict[str, Any], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        load_catalog(write_catalog(tmp_path, **over))


# ---------------------------------------------------------------- plan


def test_plan_covers_every_build_kind() -> None:
    jobs = plan(catalog())
    assert [(j.name, j.kind, j.ref) for j in jobs] == [
        ("haproxy", "apko", "haproxy:3.4.7-r1"),
        ("spire-server", "melange", "spire-server:1.15.5-r0"),
    ]
    assert jobs[0].smoke == Smoke(("-v",), "HAProxy version")
    assert jobs[1].package == "melange/spire.yaml"


def test_only_filters_and_rejects_unknown_names() -> None:
    assert [j.name for j in plan(catalog(), {"haproxy"})] == ["haproxy"]
    with pytest.raises(ValueError, match="not in the catalog: nope"):
        plan(catalog(), {"nope"})


# ---------------------------------------------------------------- gate


def grype(*matches: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "matches": [
            {
                "vulnerability": {"id": vid, "severity": sev, "fix": {"state": "fixed"}},
                "artifact": {"name": pkg, "version": "1.0"},
            }
            for vid, sev, pkg in matches
        ]
    }


def exception(**over: Any) -> dict[str, Any]:
    e = {
        "image": "haproxy",
        "id": "CVE-1",
        "package": "openssl",
        "reason": "not reachable",
        "owner": "x",
        "expires": dt.date(2026, 12, 31),
    }
    e.update(over)
    return e


def test_gate_passes_below_threshold() -> None:
    g = gate(grype(("CVE-1", "Medium", "openssl"), ("CVE-2", "Low", "zlib")), "haproxy", "high", [], TODAY)
    assert g.passed
    assert g.total == 2


@pytest.mark.parametrize(
    ("threshold", "blocked"),
    [("critical", ["CVE-C"]), ("high", ["CVE-C", "CVE-H"]), ("medium", ["CVE-C", "CVE-H", "CVE-M"])],
)
def test_gate_blocks_at_and_above_threshold(threshold: str, blocked: list[str]) -> None:
    report = grype(("CVE-C", "Critical", "a"), ("CVE-H", "High", "b"), ("CVE-M", "Medium", "c"))
    g = gate(report, "haproxy", threshold, [], TODAY)
    assert not g.passed
    assert sorted(f.id for f in g.blocking) == blocked


def test_unknown_severity_is_reported_not_blocking() -> None:
    g = gate(grype(("GHSA-x", "Unknown", "a")), "haproxy", "medium", [], TODAY)
    assert g.passed
    assert g.unknown == 1


def test_exception_accepts_with_reason() -> None:
    g = gate(grype(("CVE-1", "Critical", "openssl")), "haproxy", "high", [exception()], TODAY)
    assert g.passed
    assert [(f.id, r) for f, r in g.accepted] == [("CVE-1", "not reachable")]


@pytest.mark.parametrize(
    "exc",
    [
        exception(expires=dt.date(2026, 11, 14)),  # expired
        exception(image="spire-server"),  # another image
        exception(package="zlib"),  # another package
    ],
)
def test_exception_that_does_not_match_does_not_apply(exc: dict[str, Any]) -> None:
    assert not gate(grype(("CVE-1", "Critical", "openssl")), "haproxy", "high", [exc], TODAY).passed


def test_unknown_threshold_is_an_error() -> None:
    with pytest.raises(ValueError, match="unknown severity threshold"):
        gate(grype(), "haproxy", "severe", [], TODAY)


def test_repo_exceptions_file_loads() -> None:
    load_exceptions(REPO / "cve-exceptions.yaml")


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({k: v for k, v in exception().items() if k != "reason"}, "lacks reason"),
        (exception(image="*"), "wildcard"),
        (exception(reason="  "), "empty reason"),
    ],
)
def test_bad_exceptions_are_refused(tmp_path: Path, entry: dict[str, Any], error: str) -> None:
    f = tmp_path / "exc.yaml"
    f.write_text(yaml.safe_dump({"exceptions": [entry]}))
    with pytest.raises(ValueError, match=error):
        load_exceptions(f)


# ---------------------------------------------------------------- lint


def test_repo_recipes_lint_clean() -> None:
    assert lint(REPO, repo_catalog()) == []


def test_lint_command_is_clean() -> None:
    assert main(["lint", "--root", str(REPO)]) == 0


@pytest.fixture
def repo_copy(tmp_path: Path) -> Path:
    for d in ("apko", "melange"):
        shutil.copytree(REPO / d, tmp_path / d)
    return tmp_path


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text, old
    path.write_text(text.replace(old, new, 1))


def relock(recipe: Path) -> None:
    lock = recipe.with_name(recipe.stem + ".lock.json")
    data = json.loads(lock.read_text())
    data["config"]["checksum"] = lock_checksum(recipe)
    lock.write_text(json.dumps(data))


@pytest.mark.parametrize(
    ("file", "old", "new", "problem"),
    [
        ("apko/haproxy.yaml", "haproxy-3.4-nocaps=3.4.7-r1", "haproxy-3.4-nocaps", "is not pinned"),
        (
            "apko/haproxy.yaml",
            "image.version: 3.4.7-r1",
            "image.version: 3.4.8-r0",
            "differs from the catalog tag",
        ),
        ("apko/haproxy.yaml", 'run-as: "65532"', 'run-as: "0"', "runs as '0'"),
        (
            "apko/haproxy.yaml",
            "https://packages.wolfi.dev/os\n",
            "https://example.org/os\n",
            "exactly Wolfi's",
        ),
        ("apko/spire-agent.yaml", 'run-as: "0"', 'run-as: "65532"', "runs as '65532'"),
        (
            "apko/spire-server.yaml",
            "spire-server-src=1.15.5-r0",
            "spire-server-src=1.15.4-r0",
            "builds 1.15.5-r0",
        ),
        ("melange/spire.yaml", "name: spire-agent-src", "name: spire-agent", "must end in -src"),
        ("melange/spire.yaml", "epoch: 0", "epoch: 1", "the catalog tag is 1.15.5-r0"),
        ("melange/spire.yaml", "GOTOOLCHAIN: local", "GOTOOLCHAIN: auto", "GOTOOLCHAIN=local"),
        (
            "melange/spiffe-csi-driver.yaml",
            "expected-commit: 3d52",
            "expected-commit: 3d5",
            "expected-commit",
        ),
    ],
)
def test_lint_catches_recipe_defects(repo_copy: Path, file: str, old: str, new: str, problem: str) -> None:
    recipe = repo_copy / file
    edit(recipe, old, new)
    if recipe.with_name(recipe.stem + ".lock.json").exists():
        relock(recipe)  # isolate the defect from lock staleness
    problems = lint(repo_copy, repo_catalog())
    assert any(problem in p for p in problems), problems


def test_lint_catches_stale_and_missing_locks(repo_copy: Path) -> None:
    recipe = repo_copy / "apko" / "haproxy.yaml"
    edit(recipe, "archs:", "# edited\narchs:")
    assert any("is stale" in p for p in lint(repo_copy, repo_catalog()))
    recipe.with_name("haproxy.lock.json").unlink()
    assert any("no lock file" in p for p in lint(repo_copy, repo_catalog()))


# ---------------------------------------------------------------- image checks


def job(**over: Any) -> Job:
    base: dict[str, Any] = {"name": "haproxy", "kind": "apko", "tag": "1", "recipe": "apko/haproxy.yaml"}
    base.update(over)
    return Job(**base)


def test_config_check() -> None:
    good = {"config": {"Entrypoint": ["/usr/bin/haproxy"], "User": "65532"}}
    assert check_config(job(), good) == []
    assert check_config(job(run_as_root="reason"), {"config": {"Entrypoint": ["/x"], "User": "0"}}) == []
    assert "no entrypoint" in check_config(job(), {"config": {"User": "65532"}})[0]
    assert "runs as '0'" in check_config(job(), {"config": {"Entrypoint": ["/x"]}})[0]  # empty user is root
    assert "runAsRoot is set" in check_config(job(run_as_root="reason"), good)[0]


def test_elf_interpreter(tmp_path: Path) -> None:
    interp = elf_interpreter(Path(sys.executable).resolve())
    assert interp is not None
    assert "ld-linux" in interp or "ld-musl" in interp
    static = tmp_path / "static"
    # A minimal 64-bit LE ELF header with no program headers: no interpreter.
    static.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
    assert elf_interpreter(static) is None
    (tmp_path / "script").write_text("#!/bin/sh\n")
    assert elf_interpreter(tmp_path / "script") is None


def test_smoke_uses_the_images_own_loader(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr" / "bin").mkdir(parents=True)
    shutil.copy(Path(sys.executable).resolve(), rootfs / "usr" / "bin" / "dyn")
    argv = smoke_argv(rootfs, ["/usr/bin/dyn"], ["-v"])
    assert argv[0].startswith(str(rootfs))
    assert argv[1] == "--library-path"
    assert argv[-2:] == [str(rootfs / "usr/bin/dyn"), "-v"]
    (rootfs / "usr" / "bin" / "static").write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
    assert smoke_argv(rootfs, ["/usr/bin/static"], ["-v"]) == [str(rootfs / "usr/bin/static"), "-v"]


# ---------------------------------------------------------------- signing


def test_keyless_signing_uses_the_ambient_identity_and_verifies_it_exactly() -> None:
    s = Signer(IDENTITY, ISSUER)
    assert s.keyless
    assert s.sign("cosign", "r@d") == ["cosign", "sign", "--yes", "r@d"]
    v = s.verify("cosign", "r@d")
    assert v[v.index("--certificate-identity") + 1] == IDENTITY
    assert v[v.index("--certificate-oidc-issuer") + 1] == ISSUER
    assert "--certificate-identity-regexp" not in v
    assert not [a for a in v if "insecure" in a]


def test_key_signing_skips_the_transparency_log(tmp_path: Path) -> None:
    s = Signer(IDENTITY, ISSUER, "cosign.key", tmp_path / "sc.json")
    sign = s.sign("cosign", "r@d")
    assert sign[sign.index("--key") + 1] == "cosign.key"
    assert sign[sign.index("--signing-config") + 1] == str(tmp_path / "sc.json")
    v = s.verify("cosign", "r@d")
    assert v[v.index("--key") + 1] == "cosign.pub"
    assert "--insecure-ignore-tlog=true" in v
    kms = Signer(IDENTITY, ISSUER, "awskms:///alias/k", tmp_path / "sc.json")
    assert kms.verify("cosign", "r@d")[2:4] == ["--key", "awskms:///alias/k"]


# ---------------------------------------------------------------- publish order


class FakeRunner:
    """Records commands; answers crane digest/config and writes grype reports.

    ``published`` maps target references (repo:tag) to a digest, standing in for
    images already in a target; ``signed`` lists the references that verify."""

    def __init__(
        self,
        findings: dict[str, Any],
        smoke_output: str = "",
        published: dict[str, str] | None = None,
        signed: set[str] | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.findings = findings
        self.smoke_output = smoke_output
        self.published = published or {}
        self.signed = signed or set()

    def __call__(self, argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append(argv)
        tool = Path(argv[0]).name
        out, rc = "", 0
        if tool == "crane" and argv[1] == "digest" and argv[-1].startswith("localhost"):
            out = "sha256:" + ("a" if "--platform" in argv else "b") * 64
        elif tool == "crane" and argv[1] == "digest":
            if "--platform" in argv:
                out = "sha256:" + "c" * 64
            elif argv[-1] in self.published:
                out = self.published[argv[-1]]
            else:
                rc = 1
        elif tool == "cosign" and argv[1] == "verify" and not kw.get("check", True):
            rc = 0 if argv[-1] in self.signed else 1
        elif tool == "crane" and argv[1] == "config":
            out = json.dumps({"config": {"Entrypoint": ["/usr/bin/haproxy"], "User": "65532"}})
        elif tool == "grype":
            Path(argv[argv.index("--file") + 1]).write_text(json.dumps(self.findings))
        elif tool == "crane" and argv[1] == "export":
            src = Path(argv[-1]).with_name("src")
            (src / "usr" / "bin").mkdir(parents=True)
            (src / "usr" / "bin" / "haproxy").write_text("#!/bin/sh\n")
            with tarfile.open(argv[-1], "w") as t:
                t.add(src / "usr", arcname="usr")
        elif tool == "haproxy":  # the smoke run itself
            out = self.smoke_output
        return subprocess.CompletedProcess(argv, rc, out, "")

    def tools_used(self) -> list[tuple[str, str]]:
        return [(Path(c[0]).name, c[1]) for c in self.calls]


TARGETS = ["ghcr.io/o/r", "registry.example/mirror"]


def factory(
    tmp_path: Path,
    runner: FakeRunner,
    signer: Signer | None = None,
    skip_existing: bool = False,
    archs: Sequence[str] = ("x86_64",),
) -> Factory:
    b = Builder(REPO, tmp_path, Tools(tmp_path / "bin"), list(archs), "localhost:1", run=runner)
    return Factory(
        b, "high", signer or Signer(IDENTITY, ISSUER), [], TARGETS, TODAY, skip_existing=skip_existing
    )


def test_publish_signs_and_attests_at_every_target(tmp_path: Path) -> None:
    runner = FakeRunner(grype(("CVE-1", "Medium", "a")))
    result = factory(tmp_path, runner).publish(job())
    used = runner.tools_used()
    assert ("apko", "publish") in used
    copies = [c[-1] for c in runner.calls if c[:2] == ["crane", "copy"]]
    assert copies == ["ghcr.io/o/r/haproxy:1", "registry.example/mirror/haproxy:1"]
    for target in TARGETS:
        signed = [c for c in runner.calls if c[:2] == ["cosign", "sign"] and c[-1].startswith(target)]
        attested = [c for c in runner.calls if c[:2] == ["cosign", "attest"] and c[-1].startswith(target)]
        verified = [c for c in runner.calls if c[:2] == ["cosign", "verify"] and c[-1].startswith(target)]
        assert len(signed) == 2  # the index and the architecture's manifest
        assert len(attested) == 1
        assert verified
    assert result.references == [
        "ghcr.io/o/r/haproxy:1@sha256:" + "b" * 64,
        "registry.example/mirror/haproxy:1@sha256:" + "b" * 64,
    ]
    assert result.platforms == {"linux/amd64": "sha256:" + "a" * 64}
    assert not result.reused
    gate_json = json.loads((tmp_path / "haproxy/gate.json").read_text())
    assert gate_json["platforms"]["linux/amd64"]["total"] == 1


def test_gate_failure_publishes_nothing(tmp_path: Path) -> None:
    runner = FakeRunner(grype(("CVE-9", "Critical", "openssl")))
    with pytest.raises(SystemExit, match="CVE gate failed at high"):
        factory(tmp_path, runner).publish(job())
    used = runner.tools_used()
    assert ("crane", "copy") not in used
    assert not [t for t in used if t[0] == "cosign"]


def test_config_failure_publishes_nothing(tmp_path: Path) -> None:
    runner = FakeRunner(grype())
    with pytest.raises(SystemExit, match="runAsRoot is set"):
        factory(tmp_path, runner).publish(job(run_as_root="reason"))
    assert ("crane", "copy") not in runner.tools_used()


def test_melange_builds_then_assembles_with_the_local_repo(tmp_path: Path) -> None:
    runner = FakeRunner(grype())
    b = Builder(REPO, tmp_path, Tools(tmp_path / "bin"), ["x86_64"], "localhost:1", run=runner)
    b.build(
        job(
            name="spire-server", kind="melange", recipe="apko/spire-server.yaml", package="melange/spire.yaml"
        )
    )
    b.build(
        job(name="spire-agent", kind="melange", recipe="apko/spire-agent.yaml", package="melange/spire.yaml")
    )
    assert runner.tools_used().count(("melange", "keygen")) == 1
    apko = next(c for c in runner.calls if c[:2] == ["apko", "publish"])
    assert apko[apko.index("--repository-append") + 1] == str(tmp_path / "packages")
    assert apko[apko.index("--keyring-append") + 1] == str(tmp_path / "melange.rsa.pub")


@pytest.mark.parametrize(
    ("output", "passes"), [("HAProxy version 3.4.7 2026/10/14", True), ("bash: not found", False)]
)
def test_smoke_test_gates_publishing(tmp_path: Path, output: str, passes: bool) -> None:
    runner = FakeRunner(grype(), smoke_output=output)
    f = factory(tmp_path, runner, archs=[HOST_ARCH])
    smoke_job = job(smoke=Smoke(("-v",), "HAProxy version 3.4.7"))
    if passes:
        assert f.publish(smoke_job).smoke.startswith("HAProxy version 3.4.7")
    else:
        with pytest.raises(SystemExit, match="smoke test expected"):
            f.publish(smoke_job)
        assert ("crane", "copy") not in runner.tools_used()


def test_architectures_per_job(tmp_path: Path) -> None:
    other = "aarch64" if HOST_ARCH == "x86_64" else "x86_64"
    b = Builder(REPO, tmp_path, Tools(tmp_path), [HOST_ARCH, other], "localhost:1")
    assert b.archs_for(job(kind="apko")) == [HOST_ARCH, other]
    assert b.archs_for(job(kind="melange")) == [HOST_ARCH]  # no emulation by default
    b.cross = True
    assert b.archs_for(job(kind="melange")) == [HOST_ARCH, other]


# ---------------------------------------------------------------- skip existing

DIGEST = "sha256:" + "d" * 64


def published_everywhere() -> dict[str, str]:
    return {f"{t}/haproxy:1": DIGEST for t in TARGETS}


def signed_everywhere() -> set[str]:
    return {f"{t}/haproxy@{DIGEST}" for t in TARGETS}


def test_skip_existing_reuses_a_signed_image(tmp_path: Path) -> None:
    runner = FakeRunner(grype(), published=published_everywhere(), signed=signed_everywhere())
    r = factory(tmp_path, runner, skip_existing=True).publish(job())
    assert r.reused
    assert r.digest == DIGEST
    assert r.references == [f"{t}/haproxy:1@{DIGEST}" for t in TARGETS]
    used = runner.tools_used()
    assert ("apko", "publish") not in used
    assert ("crane", "copy") not in used
    assert ("cosign", "sign") not in used


@pytest.mark.parametrize(
    ("published", "signed"),
    [
        ({}, set()),  # not published anywhere
        ({"ghcr.io/o/r/haproxy:1": DIGEST}, {f"ghcr.io/o/r/haproxy@{DIGEST}"}),  # one target only
        (published_everywhere(), {f"ghcr.io/o/r/haproxy@{DIGEST}"}),  # unsigned at one target
        ({**published_everywhere(), "registry.example/mirror/haproxy:1": "sha256:" + "e" * 64}, None),
    ],
)
def test_skip_existing_rebuilds_unless_every_target_is_signed(
    tmp_path: Path, published: dict[str, str], signed: set[str] | None
) -> None:
    if signed is None:  # different digests per target, each signed
        signed = {f"ghcr.io/o/r/haproxy@{DIGEST}", "registry.example/mirror/haproxy@sha256:" + "e" * 64}
    runner = FakeRunner(grype(), published=published, signed=signed)
    r = factory(tmp_path, runner, skip_existing=True).publish(job())
    assert not r.reused
    assert ("apko", "publish") in runner.tools_used()


def test_without_skip_existing_always_builds(tmp_path: Path) -> None:
    runner = FakeRunner(grype(), published=published_everywhere(), signed=signed_everywhere())
    assert not factory(tmp_path, runner).publish(job()).reused
    assert ("apko", "publish") in runner.tools_used()


# ---------------------------------------------------------------- release manifest


def test_release_manifest_records_identity_source_and_digests(tmp_path: Path) -> None:
    runner = FakeRunner(grype())
    r = factory(tmp_path, runner).publish(job())
    now = dt.datetime(2026, 11, 16, 12, 0, tzinfo=dt.UTC)
    src = {"repository": "https://github.com/o/r", "commit": "c" * 40, "run": "1"}
    m = release_manifest([r], Signer(IDENTITY, ISSUER), src, now)
    assert m["apiVersion"] == RELEASE_API
    assert m["createdAt"] == "2026-11-16T12:00:00+00:00"
    assert m["signing"] == {"mode": "keyless", "identity": IDENTITY, "issuer": ISSUER}
    assert m["source"] == src
    (image,) = m["images"]
    assert image["name"] == "haproxy"
    assert image["digest"] == "sha256:" + "b" * 64
    assert image["platforms"] == {"linux/amd64": "sha256:" + "a" * 64}
    assert image["reused"] is False
    json.dumps(m)  # serialisable
    keyed = release_manifest([r], Signer(IDENTITY, ISSUER, "k", tmp_path / "sc"), src, now)
    assert keyed["signing"] == {"mode": "key"}
