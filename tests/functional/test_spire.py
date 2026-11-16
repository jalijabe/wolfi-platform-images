"""SPIRE server and agent work together: the server mints X.509-SVIDs from its
CA, an agent attests with a join token and serves the Workload API, a
registered workload gets its SPIFFE ID, an unregistered one gets none, and an
agent with a forged token is refused. Both run with a read-only root
filesystem, every capability dropped and no-new-privileges."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509

from tests.functional.helpers import HARDENED, docker, logs, wait_for

pytestmark = pytest.mark.image("spire-server", "spire-agent")

TRUST_DOMAIN = "example.org"
SERVER_SOCKET = "/run/spire/sockets/server.sock"
AGENT_SOCKET = "/run/spire/sockets/agent.sock"

SERVER_CONF = f"""\
server {{
  bind_address = "0.0.0.0"
  bind_port = "8081"
  socket_path = "{SERVER_SOCKET}"
  trust_domain = "{TRUST_DOMAIN}"
  data_dir = "/run/spire/data"
  log_level = "DEBUG"
}}

plugins {{
  DataStore "sql" {{
    plugin_data {{
      database_type = "sqlite3"
      connection_string = "/run/spire/data/datastore.sqlite3"
    }}
  }}
  KeyManager "memory" {{
    plugin_data {{}}
  }}
  NodeAttestor "join_token" {{
    plugin_data {{}}
  }}
}}

health_checks {{
  listener_enabled = true
  bind_address = "0.0.0.0"
  bind_port = "8080"
  live_path = "/live"
  ready_path = "/ready"
}}
"""

AGENT_CONF = f"""\
agent {{
  data_dir = "/run/spire/data"
  log_level = "DEBUG"
  server_address = "spire-server"
  server_port = "8081"
  socket_path = "{AGENT_SOCKET}"
  trust_bundle_path = "/etc/spire/bundle.crt"
  trust_domain = "{TRUST_DOMAIN}"
}}

plugins {{
  NodeAttestor "join_token" {{
    plugin_data {{}}
  }}
  KeyManager "memory" {{
    plugin_data {{}}
  }}
  WorkloadAttestor "unix" {{
    plugin_data {{}}
  }}
}}
"""

# Writable state lives on tmpfs, owned by the user each image runs as.
SERVER_TMPFS = [f"--tmpfs=/run/spire/{d}:uid=65532,gid=65532" for d in ("data", "sockets")]
AGENT_TMPFS = ["--tmpfs=/run/spire/data", "--tmpfs=/run/spire/sockets"]


def conf_dir(path: Path, files: dict[str, str]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o755)
    for name, text in files.items():
        (path / name).write_text(text)
        (path / name).chmod(0o644)
    return path


def server_cli(server: str, *args: str, check: bool = True) -> str:
    r = docker("exec", server, "/usr/bin/spire-server", *args, "-socketPath", SERVER_SOCKET, check=check)
    return r.stdout + r.stderr


def agent_fetch(agent: str, *exec_opts: str, timeout: str = "5s") -> tuple[int, str]:
    r = docker("exec", *exec_opts, agent, "/usr/bin/spire-agent", "api", "fetch", "x509",
               "-socketPath", AGENT_SOCKET, "-timeout", timeout, check=False)  # fmt: skip
    return r.returncode, r.stdout + r.stderr


def healthy(container: str, binary: str, socket: str) -> bool:
    r = docker("exec", container, f"/usr/bin/{binary}", "healthcheck", "-socketPath", socket, check=False)
    return r.returncode == 0


def pem_certs(text: str) -> list[x509.Certificate]:
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S)
    return [x509.load_pem_x509_certificate(b.encode()) for b in blocks]


def spiffe_ids(cert: x509.Certificate) -> list[str]:
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return [str(u) for u in san.get_values_for_type(x509.UniformResourceIdentifier)]


@pytest.fixture(scope="module")
def spire(
    image: Callable[[str], str],
    network: str,
    containers: list[str],
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:8]
    server, agent = f"spire-server-{suffix}", f"spire-agent-{suffix}"
    sconf = conf_dir(tmp_path_factory.mktemp("server"), {"server.conf": SERVER_CONF})
    docker("run", "-d", "--name", server, "--network", network, "--network-alias", "spire-server",
           *HARDENED, *SERVER_TMPFS, "-v", f"{sconf}:/etc/spire:ro",
           image("spire-server"), "-config", "/etc/spire/server.conf")  # fmt: skip
    containers.append(server)
    try:
        wait_for(lambda: healthy(server, "spire-server", SERVER_SOCKET), 60, "the SPIRE server")
    except AssertionError:
        pytest.fail(f"SPIRE server never became healthy\n{logs(server)}")

    bundle = server_cli(server, "bundle", "show")
    token = re.search(r"Token: (\S+)", server_cli(server, "token", "generate", "-spiffeID",
                                                     f"spiffe://{TRUST_DOMAIN}/agent"))  # fmt: skip
    assert token, "no join token"
    server_cli(server, "entry", "create", "-parentID", f"spiffe://{TRUST_DOMAIN}/agent",
               "-spiffeID", f"spiffe://{TRUST_DOMAIN}/workload", "-selector", "unix:uid:0")  # fmt: skip

    aconf = conf_dir(tmp_path_factory.mktemp("agent"), {"agent.conf": AGENT_CONF, "bundle.crt": bundle})
    docker("run", "-d", "--name", agent, "--network", network, *HARDENED, *AGENT_TMPFS,
           "-v", f"{aconf}:/etc/spire:ro", image("spire-agent"),
           "-config", "/etc/spire/agent.conf", "-joinToken", token.group(1))  # fmt: skip
    containers.append(agent)
    try:
        wait_for(lambda: healthy(agent, "spire-agent", AGENT_SOCKET), 60, "the SPIRE agent")
    except AssertionError:
        pytest.fail(f"SPIRE agent never became healthy\n--- agent\n{logs(agent)}\n--- server\n{logs(server)}")
    return {"server": server, "agent": agent, "bundle": bundle, "network": network, "aconf": aconf}


def test_server_mints_svids_from_its_ca(spire: dict[str, Any]) -> None:
    out = server_cli(spire["server"], "x509", "mint", "-spiffeID", f"spiffe://{TRUST_DOMAIN}/minted")
    certs = pem_certs(out)
    assert certs, out
    assert spiffe_ids(certs[0]) == [f"spiffe://{TRUST_DOMAIN}/minted"]
    ca = pem_certs(spire["bundle"])[0]
    certs[0].verify_directly_issued_by(ca)  # raises unless the bundle's CA signed it


def test_agent_attests_with_a_join_token(spire: dict[str, Any]) -> None:
    agents = server_cli(spire["server"], "agent", "list")
    assert "join_token" in agents, agents


def test_registered_workload_gets_its_spiffe_id(spire: dict[str, Any]) -> None:
    want = f"spiffe://{TRUST_DOMAIN}/workload"
    result: dict[str, str] = {}

    def fetched() -> bool:
        rc, out = agent_fetch(spire["agent"])
        result["out"] = out
        return rc == 0 and want in out

    try:
        wait_for(fetched, 90, "the workload's SVID", interval=2)
    except AssertionError:
        pytest.fail(f"no SVID for the workload\n{result.get('out')}\n--- agent\n{logs(spire['agent'])}")


def test_unregistered_workload_gets_no_identity(spire: dict[str, Any]) -> None:
    test_registered_workload_gets_its_spiffe_id(spire)  # the agent has synced its entries
    rc, out = agent_fetch(spire["agent"], "-u", "4242")
    assert rc != 0, out
    assert "spiffe://" not in out


def test_agent_with_a_forged_token_is_refused(
    spire: dict[str, Any], image: Callable[[str], str], containers: list[str]
) -> None:
    rogue = f"spire-agent-rogue-{uuid.uuid4().hex[:8]}"
    docker("run", "-d", "--name", rogue, "--network", spire["network"], *HARDENED, *AGENT_TMPFS,
           "-v", f"{spire['aconf']}:/etc/spire:ro", image("spire-agent"),
           "-config", "/etc/spire/agent.conf", "-joinToken", str(uuid.uuid4()))  # fmt: skip
    containers.append(rogue)
    wait_for(lambda: docker("inspect", "-f", "{{.State.Running}}", rogue).stdout.strip() == "false",
             60, "the rogue agent to give up")  # fmt: skip
    code = docker("inspect", "-f", "{{.State.ExitCode}}", rogue).stdout.strip()
    assert code != "0", logs(rogue)
    attested = re.findall(r"SPIFFE ID\s*:\s*(\S+)", server_cli(spire["server"], "agent", "list"))
    assert len(attested) == 1, attested  # only the legitimate agent


def test_both_run_hardened(spire: dict[str, Any]) -> None:
    for name, user in ((spire["server"], "65532"), (spire["agent"], "0")):
        fmt = "{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}"
        got = docker("inspect", "-f", fmt, name).stdout.split()
        assert got[0] == user, (name, got)
        assert got[1] == "true"
        assert "ALL" in " ".join(got[2:])
