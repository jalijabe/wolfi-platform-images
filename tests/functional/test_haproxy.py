"""HAProxy works: it validates configuration, proxies HTTP to a healthy backend,
reports an unhealthy one, serves its stats page, and does all of it as a
non-root user with every capability dropped on a read-only root filesystem."""

from __future__ import annotations

import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.functional.helpers import HARDENED, docker, logs, wait_for

pytestmark = pytest.mark.image("haproxy")

CONFIG_DIR = "/usr/local/etc/haproxy"

UPSTREAM = """\
global
  log stdout format raw local0
defaults
  mode http
  timeout connect 5s
  timeout client 10s
  timeout server 10s
frontend upstream
  bind :8081
  http-request return status 200 content-type text/plain string "hello from upstream"
"""

PROXY = """\
global
  log stdout format raw local0
defaults
  mode http
  log global
  option httplog
  timeout connect 2s
  timeout client 10s
  timeout server 10s
frontend web
  bind :8080
  http-response set-header X-Proxied-By haproxy
  use_backend dead if { path_beg /dead }
  default_backend app
backend app
  server upstream upstream:8081 check inter 1s
backend dead
  server nothing 127.0.0.1:9 check inter 1s
listen stats
  bind :8404
  stats enable
  stats uri /stats
"""


def get(url: str) -> tuple[int, dict[str, str], str]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 - http to a local test container
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def config_dir(tmp: Path, text: str) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "haproxy.cfg").write_text(text)
    tmp.chmod(0o755)
    (tmp / "haproxy.cfg").chmod(0o644)
    return tmp


@pytest.fixture(scope="module")
def proxy(
    image: Callable[[str], str],
    network: str,
    containers: list[str],
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Any]:
    img = image("haproxy")
    suffix = uuid.uuid4().hex[:8]
    up = f"haproxy-upstream-{suffix}"
    px = f"haproxy-proxy-{suffix}"
    up_cfg = config_dir(tmp_path_factory.mktemp("upstream"), UPSTREAM)
    px_cfg = config_dir(tmp_path_factory.mktemp("proxy"), PROXY)
    for name, cfg, extra in (
        (up, up_cfg, ("--network-alias", "upstream")),
        (px, px_cfg, ("-p", "127.0.0.1::8080", "-p", "127.0.0.1::8404")),
    ):
        docker("run", "-d", "--name", name, "--network", network, *extra, *HARDENED,
               "-v", f"{cfg}:{CONFIG_DIR}:ro", img)  # fmt: skip
        containers.append(name)
    ports = {p: docker("port", px, f"{p}/tcp").stdout.split(":")[-1].strip() for p in (8080, 8404)}
    base = f"http://127.0.0.1:{ports[8080]}"
    try:
        wait_for(lambda: get(base + "/")[0] == 200, 30, "the proxy to serve through the healthy backend")
    except AssertionError:
        pytest.fail(f"proxy never became ready\n--- proxy\n{logs(px)}\n--- upstream\n{logs(up)}")
    return {"name": px, "base": base, "stats": f"http://127.0.0.1:{ports[8404]}/stats", "image": img}


def test_valid_configuration_is_accepted(image: Callable[[str], str], tmp_path: Path) -> None:
    cfg = config_dir(tmp_path, PROXY.replace("upstream:8081", "127.0.0.1:8081"))
    r = docker("run", "--rm", *HARDENED, "-v", f"{cfg}:{CONFIG_DIR}:ro", image("haproxy"),
               "-c", "-f", f"{CONFIG_DIR}/haproxy.cfg", check=False)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr  # haproxy -c is silent on success


def test_invalid_configuration_is_rejected(image: Callable[[str], str], tmp_path: Path) -> None:
    cfg = config_dir(tmp_path, PROXY + "frontend broken\n  bind :notaport\n")
    r = docker("run", "--rm", *HARDENED, "-v", f"{cfg}:{CONFIG_DIR}:ro", image("haproxy"),
               "-c", "-f", f"{CONFIG_DIR}/haproxy.cfg", check=False)  # fmt: skip
    assert r.returncode != 0


def test_proxies_requests_to_a_healthy_backend(proxy: dict[str, Any]) -> None:
    status, headers, body = get(proxy["base"] + "/anything")
    assert status == 200
    assert body == "hello from upstream"
    assert headers.get("x-proxied-by") == "haproxy"


def test_reports_an_unavailable_backend(proxy: dict[str, Any]) -> None:
    status, _, _ = get(proxy["base"] + "/dead")
    assert status == 503


def test_serves_its_stats_page(proxy: dict[str, Any]) -> None:
    status, _, body = get(proxy["stats"])
    assert status == 200
    assert "Statistics Report" in body


def test_runs_unprivileged_and_hardened(proxy: dict[str, Any]) -> None:
    fmt = "{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}"
    inspect = docker("inspect", "-f", fmt, proxy["name"]).stdout.split()
    assert inspect[0] == "65532"
    assert inspect[1] == "true"
    assert "ALL" in " ".join(inspect[2:])
    rows = docker("top", proxy["name"], "-eo", "pid,uid").stdout.splitlines()[1:]
    uids = {row.split()[1] for row in rows}
    assert rows, "no processes"
    assert uids == {"65532"}, rows  # the master and every worker


def test_image_has_no_shell(image: Callable[[str], str]) -> None:
    r = docker("run", "--rm", "--entrypoint", "/bin/sh", image("haproxy"), "-c", "true", check=False)
    assert r.returncode != 0
