"""Helpers shared by the functional tests."""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


def run(*argv: str, check: bool = True, timeout: float = 300, **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), capture_output=True, text=True, check=check, timeout=timeout, **kw)


def tool(name: str) -> str:
    """A pinned tool from .bin (FACTORY_BIN), else from PATH."""
    p = Path(os.environ.get("FACTORY_BIN", Path(__file__).resolve().parents[2] / ".bin")) / name
    return str(p) if p.exists() else name


def docker(*argv: str, check: bool = True, timeout: float = 300) -> subprocess.CompletedProcess[str]:
    return run("docker", *argv, check=check, timeout=timeout)


def wait_for(probe: Callable[[], bool], timeout: float, what: str, interval: float = 1.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what}")


def logs(container: str) -> str:
    r = docker("logs", container, check=False)
    return (r.stdout + r.stderr)[-4000:]


HARDENED = ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")
