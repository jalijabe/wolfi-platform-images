"""Image factory: build, check, gate, sign and publish the images in images.yaml.

For each image the factory:

1. builds it into a local staging registry (apko, or melange then apko for
   packages built from source);
2. checks the image config and runs a smoke test from its own root filesystem;
3. writes an SPDX SBOM (syft) and scans the image (grype), per architecture;
4. applies the CVE gate: findings at or above ``maxCveSeverity`` block
   publishing unless ``cve-exceptions.yaml`` accepts them with a reason, an
   owner and an unexpired date;
5. copies the image to every target registry (same digest), signs it and
   attests the SBOM there with cosign, and verifies both.

Nothing reaches a target before the gate passes. ``build`` publishes to a
staging registry; the functional tests (``tests/functional``) run against
those exact digests; ``promote`` then copies only images whose functional
tests all passed to the real target and signs them there. Signing is keyless (GitHub
OIDC, Fulcio and Rekor; the identity in images.yaml) or with a key file or KMS
key and no transparency log. Every run writes ``release.json``: each image's
tag, digests per platform, references, gate summary and the source commit.

``lint`` checks the recipes offline; ``plan`` prints the build plan; ``gate``
evaluates a grype report; ``lockable`` lists the recipes that carry a lock file.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Grype severities, lowest first. "unknown" never blocks; it is reported.
SEVERITIES = ("negligible", "low", "medium", "high", "critical")
WOLFI_REPO = "https://packages.wolfi.dev/os"
WOLFI_KEY = "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"
HOST_ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(
    platform.machine(), platform.machine()
)
OCI_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
RELEASE_API = "wolfi-platform-images/release/v1"

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TAG_RE = re.compile(r"^[0-9][0-9A-Za-z.+_-]*$")
RECIPE_RE = re.compile(r"^apko/[a-z0-9-]+\.yaml$")
PACKAGE_RE = re.compile(r"^melange/[a-z0-9-]+\.yaml$")


# ---------------------------------------------------------------- model


@dataclass(frozen=True)
class Smoke:
    args: tuple[str, ...]
    expect: str


@dataclass(frozen=True)
class Job:
    """One image to build and publish."""

    name: str
    kind: str  # "apko" or "melange"
    tag: str
    recipe: str
    package: str | None = None  # melange recipe (kind "melange")
    smoke: Smoke | None = None
    run_as_root: str | None = None

    @property
    def ref(self) -> str:
        return f"{self.name}:{self.tag}"


@dataclass(frozen=True)
class Catalog:
    registry: str
    max_cve_severity: str
    archs: tuple[str, ...]
    identity: str
    issuer: str
    images: dict[str, dict[str, Any]]


def load_catalog(path: Path) -> Catalog:
    """Read and validate images.yaml."""
    data = yaml.safe_load(path.read_text()) or {}
    problems: list[str] = []
    for key in ("registry", "maxCveSeverity", "archs", "signing", "images"):
        if key not in data:
            problems.append(f"missing {key}")
    if problems:
        raise ValueError(f"{path}: {'; '.join(problems)}")
    if data["maxCveSeverity"] not in SEVERITIES:
        problems.append(f"maxCveSeverity must be one of {', '.join(SEVERITIES)}")
    bad_archs = set(data["archs"]) - set(OCI_ARCH)
    if bad_archs or not data["archs"]:
        problems.append(f"archs must be a non-empty subset of {', '.join(OCI_ARCH)}")
    signing = data["signing"] or {}
    if not str(signing.get("identity", "")).startswith("https://") or not signing.get("issuer"):
        problems.append("signing needs an https identity and an issuer")
    for name, meta in (data["images"] or {}).items():
        where = f"images.{name}"
        if not NAME_RE.fullmatch(name):
            problems.append(f"{where}: name must be lowercase letters, digits and dashes")
        if not TAG_RE.fullmatch(str(meta.get("tag", ""))):
            problems.append(f"{where}: tag {meta.get('tag')!r} is not a version")
        if not RECIPE_RE.fullmatch(str(meta.get("recipe", ""))):
            problems.append(f"{where}: recipe must be apko/<name>.yaml")
        if "package" in meta and not PACKAGE_RE.fullmatch(str(meta["package"])):
            problems.append(f"{where}: package must be melange/<name>.yaml")
        smoke = meta.get("smoke")
        if smoke is not None and not (isinstance(smoke.get("args"), list) and smoke.get("expect")):
            problems.append(f"{where}: smoke needs args (a list) and expect")
        unknown = set(meta) - {"tag", "recipe", "package", "smoke", "runAsRoot"}
        if unknown:
            problems.append(f"{where}: unknown keys {', '.join(sorted(unknown))}")
    if not data["images"]:
        problems.append("no images")
    if problems:
        raise ValueError(f"{path}: " + "; ".join(problems))
    return Catalog(
        registry=str(data["registry"]).rstrip("/"),
        max_cve_severity=data["maxCveSeverity"],
        archs=tuple(data["archs"]),
        identity=signing["identity"],
        issuer=signing["issuer"],
        images=dict(data["images"]),
    )


@dataclass
class Finding:
    id: str
    severity: str
    package: str
    version: str
    fix_state: str


@dataclass
class GateResult:
    threshold: str
    blocking: list[Finding] = field(default_factory=list)
    accepted: list[tuple[Finding, str]] = field(default_factory=list)
    unknown: int = 0
    total: int = 0

    @property
    def passed(self) -> bool:
        return not self.blocking


# ---------------------------------------------------------------- plan


def version_of(tag: object) -> str:
    """The upstream version in a tag: 3.4.7-r1 -> 3.4.7 (for smoke expectations)."""
    return str(tag).rsplit("-r", 1)[0]


def plan(catalog: Catalog, only: set[str] | None = None) -> list[Job]:
    """Build jobs for the catalog, in catalog order."""
    jobs: list[Job] = []
    for name, meta in catalog.images.items():
        smoke = (
            Smoke(
                tuple(meta["smoke"]["args"]),
                str(meta["smoke"]["expect"]).replace("{version}", version_of(meta["tag"])),
            )
            if "smoke" in meta
            else None
        )
        jobs.append(
            Job(
                name=name,
                kind="melange" if "package" in meta else "apko",
                tag=str(meta["tag"]),
                recipe=meta["recipe"],
                package=meta.get("package"),
                smoke=smoke,
                run_as_root=meta.get("runAsRoot"),
            )
        )
    if only:
        unknown = only - {j.name for j in jobs}
        if unknown:
            raise ValueError(f"not in the catalog: {', '.join(sorted(unknown))}")
        jobs = [j for j in jobs if j.name in only]
    return jobs


# ---------------------------------------------------------------- gate


def findings(grype: dict[str, Any]) -> list[Finding]:
    out = []
    for m in grype.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        out.append(
            Finding(
                id=v["id"],
                severity=str(v.get("severity", "Unknown")).lower(),
                package=a["name"],
                version=a["version"],
                fix_state=str(v.get("fix", {}).get("state", "unknown")),
            )
        )
    return out


def gate(
    grype: dict[str, Any],
    image: str,
    threshold: str,
    exceptions: Sequence[dict[str, Any]],
    today: dt.date,
) -> GateResult:
    """Apply the CVE gate: severity >= threshold blocks unless excepted."""
    if threshold not in SEVERITIES:
        raise ValueError(f"unknown severity threshold {threshold!r}")
    floor = SEVERITIES.index(threshold)
    accepted: dict[tuple[str, str], str] = {}
    for e in exceptions:
        if e["image"] != image:
            continue
        expires = e["expires"]
        if not isinstance(expires, dt.date):
            expires = dt.date.fromisoformat(str(expires))
        if expires >= today:
            accepted[(e["id"], e["package"])] = e["reason"]
    res = GateResult(threshold=threshold)
    for f in findings(grype):
        res.total += 1
        if f.severity not in SEVERITIES:
            res.unknown += 1
            continue
        if SEVERITIES.index(f.severity) < floor:
            continue
        reason = accepted.get((f.id, f.package))
        if reason is not None:
            res.accepted.append((f, reason))
        else:
            res.blocking.append(f)
    return res


def load_exceptions(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text()) or {}
    exc: list[dict[str, Any]] = data.get("exceptions") or []
    for i, e in enumerate(exc):
        missing = {"image", "id", "package", "reason", "owner", "expires"} - set(e)
        if missing:
            raise ValueError(f"{path}: exception {i} lacks {', '.join(sorted(missing))}")
        if "*" in str(e["image"]) or "*" in str(e["id"]):
            raise ValueError(f"{path}: exception {i} uses a wildcard")
        if not str(e["reason"]).strip():
            raise ValueError(f"{path}: exception {i} has an empty reason")
    return exc


# ---------------------------------------------------------------- lint


def lock_checksum(recipe: Path) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(recipe.read_bytes()).digest()).decode()


def _pins(cfg: dict[str, Any]) -> dict[str, str]:
    pins = {}
    for p in cfg.get("contents", {}).get("packages", []):
        name, _, version = str(p).partition("=")
        pins[name] = version
    return pins


def lint(root: Path, catalog: Catalog) -> list[str]:
    """Check every recipe the catalog names. Returns problems (empty = clean)."""
    problems: list[str] = []
    for name, meta in sorted(catalog.images.items()):
        recipe_path = root / meta["recipe"]
        if not recipe_path.is_file():
            problems.append(f"{name}: recipe {meta['recipe']} is missing")
            continue
        cfg = yaml.safe_load(recipe_path.read_text())
        where = f"{name} ({meta['recipe']})"
        tag = str(meta["tag"])
        pins = _pins(cfg)
        for pkg, version in pins.items():
            if not version:
                problems.append(f"{where}: package {pkg} is not pinned (use {pkg}=<version>)")
        contents = cfg.get("contents", {})
        if contents.get("repositories") != [WOLFI_REPO] or contents.get("keyring") != [WOLFI_KEY]:
            problems.append(f"{where}: repositories and keyring must be exactly Wolfi's ({WOLFI_REPO})")
        version = cfg.get("annotations", {}).get("org.opencontainers.image.version")
        if version != tag:
            problems.append(f"{where}: annotation version {version!r} differs from the catalog tag {tag!r}")
        if tag not in pins.values():
            problems.append(f"{where}: no package is pinned to the tag {tag}")
        if not cfg.get("entrypoint", {}).get("command"):
            problems.append(f"{where}: no entrypoint")
        run_as = str(cfg.get("accounts", {}).get("run-as", ""))
        if run_as == "":
            problems.append(f"{where}: accounts.run-as must be set explicitly")
        elif (run_as in ("0", "root")) != bool(meta.get("runAsRoot")):
            problems.append(
                f"{where}: runs as {run_as!r}; images run as root exactly when the catalog gives runAsRoot"
            )
        package = meta.get("package")
        if package is None:
            lock = recipe_path.with_name(recipe_path.stem + ".lock.json")
            if not lock.is_file():
                problems.append(f"{where}: no lock file {lock.name} (task images:lock)")
            elif json.loads(lock.read_text())["config"]["checksum"] != lock_checksum(recipe_path):
                problems.append(f"{where}: {lock.name} is stale (task images:lock)")
        else:
            problems += _lint_melange(root, name, str(package), pins, tag)
    return problems


def _lint_melange(root: Path, name: str, pkg: str, pins: dict[str, str], tag: str) -> list[str]:
    path = root / pkg
    if not path.is_file():
        return [f"{name}: package recipe {pkg} is missing"]
    m = yaml.safe_load(path.read_text())
    problems: list[str] = []
    names = {m["package"]["name"]} | {s["name"] for s in m.get("subpackages", [])}
    # Our packages must not share Wolfi's names: Wolfi's advisories describe
    # Wolfi's builds, and scanners would apply them to ours by name.
    problems += [
        f"{name}: {pkg} package {n} must end in -src" for n in sorted(names) if not n.endswith("-src")
    ]
    full = f"{m['package']['version']}-r{m['package']['epoch']}"
    built = [p for p in pins if p in names]
    if not built:
        problems.append(
            f"{name}: the apko recipe installs none of {pkg}'s packages ({', '.join(sorted(names))})"
        )
    for p in built:
        if pins[p] != full:
            problems.append(f"{name}: pins {p}={pins[p]} but {pkg} builds {full}")
    if full != tag:
        problems.append(f"{name}: {pkg} builds {full}, the catalog tag is {tag}")
    checkouts = [s for s in m.get("pipeline", []) if s.get("uses") == "git-checkout"]
    if not checkouts:
        problems.append(f"{name}: {pkg} has no git-checkout step")
    for s in checkouts:
        commit = str(s.get("with", {}).get("expected-commit", ""))
        commit = commit.replace("${{vars.commit}}", str(m.get("vars", {}).get("commit", "")))
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            problems.append(f"{name}: {pkg} git-checkout lacks a full expected-commit")
    env = m.get("environment", {}).get("environment", {})
    if env.get("GOTOOLCHAIN") != "local":
        problems.append(f"{name}: {pkg} must set GOTOOLCHAIN=local (never download a Go toolchain)")
    return problems


# ---------------------------------------------------------------- execution


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _run(argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(argv), file=sys.stderr, flush=True)
    kw.setdefault("check", True)
    # Never wait on a prompt (e.g. a key password): fail instead.
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(list(argv), text=True, **kw)


@dataclass
class Tools:
    bin: Path

    def __call__(self, tool: str) -> str:
        p = self.bin / tool
        return str(p) if p.exists() else tool


@contextmanager
def staging_registry(tools: Tools) -> Iterator[str]:
    """An in-memory registry on localhost for the duration of a build."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(  # long-running server, stopped below
        [tools("crane"), "registry", "serve", "--address", f"127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            with socket.socket() as c:
                if c.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        yield f"localhost:{port}"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def _need(value: str | None, job: Job, what: str) -> str:
    if value is None:
        raise ValueError(f"{job.name}: {job.kind} build needs a {what}")
    return value


@dataclass
class Builder:
    root: Path
    out: Path
    tools: Tools
    archs: list[str]
    staging: str
    run: Runner = _run
    # Source builds for another architecture need emulation (qemu binfmt).
    cross: bool = False
    _melange_key: Path | None = None

    def archs_for(self, job: Job) -> list[str]:
        """Architectures a job is built for: Wolfi-only images for every
        requested one; source builds for the host's unless cross-building is
        enabled."""
        if job.kind == "melange" and not self.cross:
            return [a for a in self.archs if a == HOST_ARCH] or [HOST_ARCH]
        return list(self.archs)

    def build(self, job: Job) -> str:
        """Build into the staging registry; return the staged reference by digest."""
        (self.out / job.name).mkdir(parents=True, exist_ok=True)
        staged = f"{self.staging}/{job.ref}"
        archs = ",".join(self.archs_for(job))
        recipe = self.root / job.recipe
        if job.kind == "apko":
            lock = recipe.with_name(recipe.stem + ".lock.json")
            self.run(
                [
                    self.tools("apko"),
                    "publish",
                    "--arch",
                    archs,
                    "--lockfile",
                    str(lock),
                    "--sbom=false",
                    str(recipe),
                    staged,
                ],
                cwd=recipe.parent,
            )
        elif job.kind == "melange":
            repo, pub = self._melange(_need(job.package, job, "package"), archs)
            self.run(
                [
                    self.tools("apko"),
                    "publish",
                    "--arch",
                    archs,
                    "--repository-append",
                    str(repo),
                    "--keyring-append",
                    str(pub),
                    "--sbom=false",
                    str(recipe),
                    staged,
                ]
            )
        else:
            raise ValueError(job.kind)
        digest = self.run([self.tools("crane"), "digest", staged], capture_output=True).stdout.strip()
        return f"{self.staging}/{job.name}@{digest}"

    def _melange(self, package: str, archs: str) -> tuple[Path, Path]:
        repo = self.out / "packages"
        if self._melange_key is None:
            # A throwaway key: it only links melange's output to this build's apko step.
            self._melange_key = self.out / "melange.rsa"
            if not self._melange_key.exists():
                self.run([self.tools("melange"), "keygen", str(self._melange_key)])
        self.run(
            [
                self.tools("melange"),
                "build",
                str(self.root / package),
                "--arch",
                archs,
                "--runner",
                "docker",
                "--signing-key",
                str(self._melange_key),
                "--out-dir",
                str(repo),
            ]
        )
        return repo, Path(str(self._melange_key) + ".pub")


def check_config(job: Job, config: dict[str, Any]) -> list[str]:
    """The image config a recipe promises: an entrypoint and the declared user."""
    c = config.get("config", {})
    problems = []
    if not c.get("Entrypoint") and not c.get("Cmd"):
        problems.append("no entrypoint or command")
    user = str(c.get("User") or "0").split(":")[0]
    if (user in ("0", "root")) != bool(job.run_as_root):
        problems.append(f"runs as {user!r}, but runAsRoot is {'set' if job.run_as_root else 'unset'}")
    return problems


def elf_interpreter(path: Path) -> str | None:
    """PT_INTERP of a 64-bit little-endian ELF, or None for static binaries."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    (phoff,) = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        off = phoff + i * phentsize
        (p_type,) = struct.unpack_from("<I", data, off)
        if p_type == 3:  # PT_INTERP
            (p_offset,) = struct.unpack_from("<Q", data, off + 8)
            (p_filesz,) = struct.unpack_from("<Q", data, off + 32)
            return data[p_offset : p_offset + p_filesz].rstrip(b"\0").decode()
    return None


def _rootfs_filter(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    if member.isdev() or member.isfifo():
        return None
    return tarfile.tar_filter(member, path)


def smoke_argv(rootfs: Path, entrypoint: Sequence[str], args: Sequence[str]) -> list[str]:
    """Run the image's entrypoint binary from its own root filesystem, through
    the image's dynamic loader when it has one (no container runtime needed)."""
    binary = rootfs / entrypoint[0].lstrip("/")
    interp = elf_interpreter(binary)
    if interp is None:
        return [str(binary), *args]
    libdirs = ":".join(str(rootfs / d) for d in ("usr/lib", "lib", "usr/lib64", "lib64"))
    return [str(rootfs / interp.lstrip("/")), "--library-path", libdirs, str(binary), *args]


# ---------------------------------------------------------------- signing


@dataclass(frozen=True)
class Signer:
    """How images are signed and verified.

    Keyless (``key`` is None): cosign's default signing config, so a Fulcio
    certificate for the ambient OIDC identity and a Rekor entry; verified
    against the exact identity and issuer. With a key file or KMS URI: a
    signing config with no services, so no transparency log; verified with
    the public key.
    """

    identity: str
    issuer: str
    key: str | None = None
    signing_config: Path | None = None

    @property
    def keyless(self) -> bool:
        return self.key is None

    def _sign_opts(self) -> list[str]:
        if self.key is None:
            return []
        return ["--key", self.key, "--signing-config", str(self.signing_config)]

    def _verify_opts(self) -> list[str]:
        if self.key is None:
            return ["--certificate-identity", self.identity, "--certificate-oidc-issuer", self.issuer]
        # cosign verifies with the KMS reference itself, or the .pub next to a key file.
        pub = self.key if "://" in self.key else str(Path(self.key).with_suffix(".pub"))
        return ["--key", pub, "--insecure-ignore-tlog=true"]

    def sign(self, cosign: str, ref: str) -> list[str]:
        return [cosign, "sign", "--yes", *self._sign_opts(), ref]

    def attest(self, cosign: str, predicate: Path, ref: str) -> list[str]:
        return [
            cosign,
            "attest",
            "--yes",
            *self._sign_opts(),
            "--type",
            "spdxjson",
            "--predicate",
            str(predicate),
            ref,
        ]

    def verify(self, cosign: str, ref: str) -> list[str]:
        return [cosign, "verify", *self._verify_opts(), ref]

    def verify_attestation(self, cosign: str, ref: str) -> list[str]:
        return [cosign, "verify-attestation", *self._verify_opts(), "--type", "spdxjson", ref]


# ---------------------------------------------------------------- publish


@dataclass
class Result:
    name: str
    tag: str
    digest: str
    platforms: dict[str, str]
    references: list[str]
    gate: dict[str, Any] | None
    smoke: str
    reused: bool = False
    # Per platform: the SBOM file, relative to the build's output directory.
    sboms: dict[str, str] = field(default_factory=dict)


class Factory:
    def __init__(
        self,
        builder: Builder,
        threshold: str,
        signer: Signer,
        exceptions: list[dict[str, Any]],
        targets: list[str],
        today: dt.date | None = None,
        reuse_from: str | None = None,
        reuse_signer: Signer | None = None,
    ) -> None:
        self.b = builder
        self.threshold = threshold
        self.signer = signer
        self.exceptions = exceptions
        self.targets = targets
        self.today = today or dt.date.today()
        self.reuse_from = reuse_from
        self.reuse_signer = reuse_signer or signer

    def _platform_digests(self, job: Job, ref: str) -> dict[str, str]:
        out = {}
        for arch in self.b.archs_for(job):
            plat = f"linux/{OCI_ARCH[arch]}"
            out[plat] = self.b.run(
                [self.b.tools("crane"), "digest", "--platform", plat, ref], capture_output=True
            ).stdout.strip()
        return out

    def existing(self, job: Job) -> Result | None:
        """The image already published at ``reuse_from`` under this tag and
        signed by the reuse signer; None if it is missing or does not verify.
        A reused image is not rebuilt: it was tested when it was published."""
        if self.reuse_from is None:
            return None
        run, tools, registry = self.b.run, self.b.tools, self.reuse_from
        r = run([tools("crane"), "digest", f"{registry}/{job.ref}"], capture_output=True, check=False)
        if r.returncode != 0:
            return None
        digest = r.stdout.strip()
        ref = f"{registry}/{job.name}@{digest}"
        v = run(self.reuse_signer.verify(tools("cosign"), ref), capture_output=True, check=False)
        if v.returncode != 0:
            return None
        return Result(
            job.name,
            job.tag,
            digest,
            self._platform_digests(job, ref),
            [f"{registry}/{job.ref}@{digest}"],
            None,
            "skipped: already published",
            reused=True,
        )

    def publish(self, job: Job) -> Result:
        found = self.existing(job)
        if found is not None:
            print(f"{job.name}: {job.ref} is already published and signed; reusing it", file=sys.stderr)
            return found
        run, tools, work = self.b.run, self.b.tools, self.b.out / job.name
        staged = self.b.build(job)
        digest = staged.rsplit("@", 1)[1]

        cfg = json.loads(
            run(
                [tools("crane"), "config", staged, "--platform", f"linux/{OCI_ARCH[HOST_ARCH]}"],
                capture_output=True,
            ).stdout
        )
        problems = check_config(job, cfg)
        if problems:
            raise SystemExit(f"{job.name}: image config: {'; '.join(problems)}")
        smoke_out = self._smoke(job, staged, cfg)

        # Per architecture: SBOM, scan and gate on that architecture's manifest.
        platforms = self._platform_digests(job, staged)
        sboms: dict[str, Path] = {}
        summary: dict[str, Any] = {"threshold": self.threshold, "platforms": {}}
        blocked: list[str] = []
        for plat in platforms:
            arch = plat.rsplit("/", 1)[1]
            sboms[plat] = work / f"sbom-{arch}.spdx.json"
            run(
                [
                    tools("syft"),
                    "scan",
                    f"registry:{staged}",
                    "--platform",
                    plat,
                    # Name the image as published, not by the ephemeral staging address.
                    "--source-name",
                    job.name,
                    "--source-version",
                    job.tag,
                    "-o",
                    f"spdx-json={sboms[plat]}",
                ]
            )
            report = work / f"grype-{arch}.json"
            run(
                [
                    tools("grype"),
                    f"registry:{staged}",
                    "--platform",
                    plat,
                    "-o",
                    "json",
                    "--file",
                    str(report),
                ]
            )
            g = gate(json.loads(report.read_text()), job.name, self.threshold, self.exceptions, self.today)
            summary["platforms"][plat] = {
                "total": g.total,
                "unknownSeverity": g.unknown,
                "accepted": [{"id": f.id, "package": f.package, "reason": r} for f, r in g.accepted],
                "blocking": [asdict(f) for f in g.blocking],
            }
            blocked += [
                f"  {plat} {f.severity:8} {f.id} {f.package} {f.version} ({f.fix_state})" for f in g.blocking
            ]
        (work / "gate.json").write_text(json.dumps(summary, indent=2) + "\n")
        if blocked:
            raise SystemExit(f"{job.name}: CVE gate failed at {self.threshold}:\n" + "\n".join(blocked))

        cosign, s = tools("cosign"), self.signer
        references = []
        for target in self.targets:
            dest = f"{target}/{job.name}"
            run([tools("crane"), "copy", staged, f"{dest}:{job.tag}"])
            # The index (what clients pull by tag) is signed; each architecture's
            # manifest is signed and carries its own SBOM attestation.
            run(s.sign(cosign, f"{dest}@{digest}"))
            run(s.verify(cosign, f"{dest}@{digest}"), capture_output=True)
            for plat, d in platforms.items():
                if d != digest:
                    run(s.sign(cosign, f"{dest}@{d}"))
                run(s.attest(cosign, sboms[plat], f"{dest}@{d}"))
                run(s.verify_attestation(cosign, f"{dest}@{d}"), capture_output=True)
            references.append(f"{dest}:{job.tag}@{digest}")
        rel = {plat: str(path.relative_to(self.b.out)) for plat, path in sboms.items()}
        return Result(job.name, job.tag, digest, platforms, references, summary, smoke_out, sboms=rel)

    def _smoke(self, job: Job, staged: str, cfg: dict[str, Any]) -> str:
        if job.smoke is None:
            return "skipped: no smoke test in the catalog"
        if HOST_ARCH not in self.b.archs_for(job):
            return f"skipped: host is {HOST_ARCH}"
        entry = list(cfg["config"].get("Entrypoint") or [])
        with tempfile.TemporaryDirectory() as tmp:
            fs = Path(tmp) / "fs.tar"
            self.b.run(
                [
                    self.b.tools("crane"),
                    "export",
                    "--platform",
                    f"linux/{OCI_ARCH[HOST_ARCH]}",
                    staged,
                    str(fs),
                ]
            )
            rootfs = Path(tmp) / "rootfs"
            with tarfile.open(fs) as t:
                # Our own freshly built image; device nodes need root and are not needed.
                t.extractall(rootfs, filter=_rootfs_filter)  # noqa: S202  # nosec B202 - tar_filter minus devices
            out = self.b.run(
                smoke_argv(rootfs, entry, job.smoke.args), capture_output=True, check=False, timeout=60
            )
        text = out.stdout + out.stderr
        if job.smoke.expect not in text:
            raise SystemExit(f"{job.name}: smoke test expected {job.smoke.expect!r}, got:\n{text[-2000:]}")
        return text.strip().splitlines()[0] if text.strip() else ""


def source_info(root: Path) -> dict[str, str]:
    """Where this build came from: the repository, commit and CI run."""
    server, repo = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
    commit = os.environ.get("GITHUB_SHA") or (
        subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False
        ).stdout.strip()
        or "unknown"
    )
    return {
        "repository": f"{server}/{repo}" if server and repo else "local",
        "commit": commit,
        "run": os.environ.get("GITHUB_RUN_ID", "local"),
    }


def release_manifest(
    results: Sequence[Result], signer: Signer, source: dict[str, str], now: dt.datetime
) -> dict[str, Any]:
    return {
        "apiVersion": RELEASE_API,
        "createdAt": now.astimezone(dt.UTC).isoformat(timespec="seconds"),
        "source": source,
        "signing": _signing_info(signer),
        "images": [asdict(r) for r in results],
    }


# ---------------------------------------------------------------- promote


def functional_summary(report: dict[str, Any], name: str) -> dict[str, Any]:
    """An image's functional-test results from the report the functional test
    suite writes (``tests/functional``): test IDs by outcome."""
    r = report.get("images", {}).get(name, {})
    passed, failed, skipped = (list(r.get(k, [])) for k in ("passed", "failed", "skipped"))
    return {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        # Passing only when something ran and nothing failed or was skipped.
        "ok": bool(passed) and not failed and not skipped,
    }


def promote(
    release: dict[str, Any],
    report: dict[str, Any],
    build_out: Path,
    targets: Sequence[str],
    signer: Signer,
    tools: Tools,
    run: Runner = _run,
) -> dict[str, Any]:
    """Copy each newly built, functionally tested image by digest from staging to
    every target, sign it and attest its SBOMs there, and verify. Refuses the
    whole promotion, before copying anything, if any built image lacks passing
    functional tests. Reused images (already published) are carried over."""
    untested = []
    for img in release["images"]:
        if img["reused"]:
            continue
        f = functional_summary(report, img["name"])
        if not f["ok"]:
            untested.append(
                f"  {img['name']}: {len(f['passed'])} passed, {len(f['failed'])} failed, "
                f"{len(f['skipped'])} skipped"
            )
    if untested:
        raise SystemExit(
            "refusing to promote images without passing functional tests:\n" + "\n".join(untested)
        )

    cosign = tools("cosign")
    images = []
    for img in release["images"]:
        if img["reused"]:
            images.append(img)
            continue
        digest, tag, name = img["digest"], img["tag"], img["name"]
        source = img["references"][0].split("@", 1)[0].rsplit(":", 1)[0]
        references = []
        for target in targets:
            dest = f"{target}/{name}"
            run([tools("crane"), "copy", f"{source}@{digest}", f"{dest}:{tag}"])
            run(signer.sign(cosign, f"{dest}@{digest}"))
            run(signer.verify(cosign, f"{dest}@{digest}"), capture_output=True)
            for plat, d in img["platforms"].items():
                if d != digest:
                    run(signer.sign(cosign, f"{dest}@{d}"))
                run(signer.attest(cosign, build_out / img["sboms"][plat], f"{dest}@{d}"))
                run(signer.verify_attestation(cosign, f"{dest}@{d}"), capture_output=True)
            references.append(f"{dest}:{tag}@{digest}")
        images.append({**img, "references": references, "functional": functional_summary(report, name)})
    return {
        "apiVersion": RELEASE_API,
        "createdAt": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "source": release["source"],
        "signing": _signing_info(signer),
        "images": images,
    }


def _signing_info(signer: Signer) -> dict[str, str]:
    if signer.keyless:
        return {"mode": "keyless", "identity": signer.identity, "issuer": signer.issuer}
    return {"mode": "key"}


# ---------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="imagefactory", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_lint = sub.add_parser("lint", help="check the catalog and recipes offline")
    p_plan = sub.add_parser("plan", help="print the build plan")
    p_gate = sub.add_parser("gate", help="apply the CVE gate to a grype JSON report")
    p_build = sub.add_parser(
        "build", help="build, gate, sign and publish (to staging, before functional tests)"
    )
    p_promote = sub.add_parser(
        "promote", help="copy functionally tested images from staging to the target, sign and verify"
    )
    p_lockable = sub.add_parser("lockable", help="list the apko recipes that carry a lock file")
    for p in (p_lint, p_plan, p_build, p_lockable, p_promote):
        p.add_argument("--root", type=Path, default=Path.cwd())
        p.add_argument("--catalog", type=Path, default=Path("images.yaml"))
    for p in (p_plan, p_build):
        p.add_argument("--only", action="append", default=[])
    p_gate.add_argument("--report", type=Path, required=True)
    p_gate.add_argument("--image", required=True)
    p_gate.add_argument("--threshold", required=True, choices=SEVERITIES)
    p_gate.add_argument("--exceptions", type=Path, default=Path("cve-exceptions.yaml"))
    for p in (p_build, p_promote):
        p.add_argument("--out", type=Path, default=Path(".build/factory"))
        p.add_argument("--bin", type=Path, default=Path(".bin"))
        signing = p.add_mutually_exclusive_group(required=True)
        signing.add_argument("--key", help="cosign key file or KMS URI (no transparency log)")
        signing.add_argument(
            "--keyless", action="store_true", help="sign with the ambient OIDC identity (Fulcio and Rekor)"
        )
        p.add_argument("--target", action="append", default=[], help="override the catalog's registry")
    p_build.add_argument("--arch", help="comma-separated, e.g. x86_64,aarch64 (default: the catalog's)")
    p_build.add_argument(
        "--reuse-from",
        help="registry to reuse images from: an image whose tag is there and verifies is not rebuilt",
    )
    p_build.add_argument(
        "--reuse-published", action="store_true", help="--reuse-from the catalog's registry (images.yaml)"
    )
    p_build.add_argument(
        "--reuse-key", help="verify reused images with this key (default: the catalog's keyless identity)"
    )
    p_promote.add_argument("--release", type=Path, required=True, help="release.json from the staging build")
    p_promote.add_argument(
        "--functional", type=Path, required=True, help="functional-test report (tests/functional)"
    )
    p_promote.add_argument(
        "--build-out", type=Path, help="the staging build's output directory (default: next to --release)"
    )
    args = ap.parse_args(argv)

    if args.cmd == "gate":
        g = gate(
            json.loads(args.report.read_text()),
            args.image,
            args.threshold,
            load_exceptions(args.exceptions),
            dt.date.today(),
        )
        for f in g.blocking:
            print(f"BLOCK {f.severity:8} {f.id} {f.package} {f.version} ({f.fix_state})")
        for finding, reason in g.accepted:
            print(f"ACCEPT {finding.severity:8} {finding.id} {finding.package}: {reason}")
        print(
            f"{args.image}: {g.total} findings, {len(g.blocking)} blocking at {g.threshold}, "
            f"{len(g.accepted)} accepted, {g.unknown} of unknown severity"
        )
        return 0 if g.passed else 1

    root = args.root.resolve()
    catalog_path = args.catalog if args.catalog.is_absolute() else root / args.catalog
    catalog = load_catalog(catalog_path)
    if args.cmd == "lockable":
        # Pure-Wolfi recipes are locked; recipes with our own melange package
        # pin their packages in the recipe (the local package changes per build).
        for meta in catalog.images.values():
            if "package" not in meta:
                print(meta["recipe"])
        return 0
    if args.cmd == "lint":
        problems = lint(root, catalog)
        try:
            load_exceptions(root / "cve-exceptions.yaml")
        except ValueError as e:
            problems.append(str(e))
        for problem in problems:
            print(f"images lint: {problem}", file=sys.stderr)
        if not problems:
            print(f"images lint: {len(catalog.images)} recipes OK")
        return 1 if problems else 0

    jobs = plan(catalog, set(args.only) or None) if args.cmd in ("plan", "build") else []
    if args.cmd == "plan":
        print(json.dumps([asdict(j) for j in jobs], indent=2))
        return 0

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    tools = Tools(args.bin.resolve())
    targets = [t.rstrip("/") for t in args.target] or [catalog.registry]
    signer = _signer(catalog, args.key, out, tools)

    if args.cmd == "promote":
        release = json.loads(args.release.read_text())
        report = json.loads(args.functional.read_text())
        build_out = (args.build_out or args.release.parent).resolve()
        manifest = promote(release, report, build_out, targets, signer, tools)
        (out / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
        for img in manifest["images"]:
            print(
                f"{'reused' if img['reused'] else 'promoted'} {img['name']}: {', '.join(img['references'])}"
            )
        return 0

    archs = args.arch.split(",") if args.arch else list(catalog.archs)
    reuse_signer = (
        _signer(catalog, args.reuse_key, out, tools)
        if args.reuse_key
        else Signer(catalog.identity, catalog.issuer)
    )
    exceptions = load_exceptions(root / "cve-exceptions.yaml")
    results = []
    # The staging registry is plain HTTP on localhost.
    os.environ.setdefault("SYFT_REGISTRY_INSECURE_USE_HTTP", "true")
    os.environ.setdefault("GRYPE_REGISTRY_INSECURE_USE_HTTP", "true")
    with staging_registry(tools) as staging:
        builder = Builder(root, out, tools, archs, staging, cross=os.environ.get("FACTORY_CROSS") == "1")
        factory = Factory(
            builder,
            catalog.max_cve_severity,
            signer,
            exceptions,
            targets,
            reuse_from=(catalog.registry if args.reuse_published else args.reuse_from or "").rstrip("/")
            or None,
            reuse_signer=reuse_signer,
        )
        for job in jobs:
            r = factory.publish(job)
            print(f"{'reused' if r.reused else 'published'} {r.name}: {', '.join(r.references)}")
            results.append(r)
    manifest = release_manifest(results, signer, source_info(root), dt.datetime.now(dt.UTC))
    (out / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


def _signer(catalog: Catalog, key: str | None, out: Path, tools: Tools) -> Signer:
    if key is None:
        return Signer(catalog.identity, catalog.issuer)
    signer = Signer(catalog.identity, catalog.issuer, key, out / "signing-config.json")
    if signer.signing_config and not signer.signing_config.exists():
        # A signing config with no services: no transparency log.
        _run([tools("cosign"), "signing-config", "create", "--out", str(signer.signing_config)])
    return signer


if __name__ == "__main__":
    sys.exit(main())
