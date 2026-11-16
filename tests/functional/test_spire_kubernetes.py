"""The SPIRE stack works on Kubernetes (kind): the server, with the controller
manager as a sidecar, attests agents with projected service-account tokens
(k8s_psat); the controller manager turns a ClusterSPIFFEID into registration
entries; the SPIFFE CSI driver mounts the Workload API into pods; a labelled
pod gets its SPIFFE ID and an unlabelled pod gets none.

Needs Docker, kind and kubectl (`task tools:functest`). The kind node image is
pinned by digest (FUNCTEST_KIND_NODE); the only image not built here is the
upstream CSI node-driver-registrar sidecar, pinned by digest."""

from __future__ import annotations

import copy
import json
import os
import string
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import yaml

from tests.functional.helpers import run, tool, wait_for

pytestmark = pytest.mark.image("spire-server", "spire-agent", "spire-controller-manager", "spiffe-csi-driver")

HERE = Path(__file__).parent / "k8s"
NODE_IMAGE = os.environ.get(
    "FUNCTEST_KIND_NODE",
    "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed",
)
REGISTRAR_IMAGE = (
    "registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.18.0"
    "@sha256:b7fefd08651f00ac4df1a196ed4c621c2451fbb899297fe9fad9e36c667af0c0"
)
WORKLOAD_ID = "spiffe://example.org/ns/functest/sa/default"
SERVER_SOCKET = "/run/spire/server-sockets/api.sock"


class Cluster:
    def __init__(self, name: str, kubeconfig: Path) -> None:
        self.name = name
        self.kubeconfig = kubeconfig
        self.values: dict[str, str] = {}

    def kubectl(self, *args: str, check: bool = True, timeout: float = 300, stdin: str | None = None) -> str:
        r = run(tool("kubectl"), "--kubeconfig", str(self.kubeconfig), *args,
                check=check, timeout=timeout, input=stdin)  # fmt: skip
        return r.stdout + (r.stderr if not check else "")

    def apply(self, manifest: str) -> None:
        r = run(tool("kubectl"), "--kubeconfig", str(self.kubeconfig), "apply", "-f", "-",
                check=False, input=manifest)  # fmt: skip
        if r.returncode != 0:
            raise AssertionError(f"kubectl apply failed:\n{r.stderr}")

    def server(self, *args: str) -> str:
        return self.kubectl("-n", "spire-system", "exec", "spire-server-0", "-c", "spire-server", "--",
                            "/usr/bin/spire-server", *args, "-socketPath", SERVER_SOCKET)  # fmt: skip

    def diagnostics(self) -> str:
        parts = [self.kubectl("get", "pods", "-A", "-o", "wide", check=False)]
        for target in ("statefulset/spire-server", "daemonset/spire-agent", "daemonset/spiffe-csi-driver"):
            parts.append(f"--- {target}")
            logs = ("logs", target, "--all-containers", "--tail", "40")
            parts.append(self.kubectl("-n", "spire-system", *logs, check=False))
        parts.append(self.kubectl("-n", "functest", "describe", "pods", check=False)[-3000:])
        return "\n".join(parts)


@pytest.fixture(scope="module")
def cluster(image: Callable[[str], str], tmp_path_factory: pytest.TempPathFactory) -> Iterator[Cluster]:
    name = f"functest-{uuid.uuid4().hex[:6]}"
    kubeconfig = tmp_path_factory.mktemp("kind") / "kubeconfig"
    run(tool("kind"), "create", "cluster", "--name", name, "--image", NODE_IMAGE,
        "--kubeconfig", str(kubeconfig), "--wait", "180s", timeout=600)  # fmt: skip
    c = Cluster(name, kubeconfig)
    try:
        images = {n: image(n) for n in ("spire-server", "spire-agent", "spire-controller-manager",
                                         "spiffe-csi-driver")}  # fmt: skip
        for ref in images.values():
            run(tool("kind"), "load", "docker-image", ref, "--name", name, timeout=600)
        for crd in sorted((HERE / "crds").glob("*.yaml")):
            c.apply(crd.read_text())
        c.kubectl("wait", "--for=condition=Established", "crd/clusterspiffeids.spire.spiffe.io",
                  "--timeout=60s")  # fmt: skip
        values = {
            "SERVER_IMAGE": images["spire-server"],
            "AGENT_IMAGE": images["spire-agent"],
            "CONTROLLER_IMAGE": images["spire-controller-manager"],
            "CSI_IMAGE": images["spiffe-csi-driver"],
            "REGISTRAR_IMAGE": REGISTRAR_IMAGE,
        }
        c.values = values
        c.apply(string.Template((HERE / "spire.yaml").read_text()).substitute(values))
        try:
            for target in (
                "statefulset/spire-server",
                "daemonset/spire-agent",
                "daemonset/spiffe-csi-driver",
            ):
                c.kubectl("-n", "spire-system", "rollout", "status", target, "--timeout=240s", timeout=300)
        except Exception:
            pytest.fail(f"SPIRE did not become ready\n{c.diagnostics()}")
        yield c
    finally:
        if os.environ.get("FUNCTEST_KEEP_CLUSTER") != "1":
            run(tool("kind"), "delete", "cluster", "--name", name, check=False, timeout=300)


def pod_logs(c: Cluster, name: str) -> str:
    return c.kubectl("-n", "functest", "logs", name, "--tail", "100", check=False)


def pod_phase(c: Cluster, name: str) -> str:
    return c.kubectl("-n", "functest", "get", "pod", name, "-o", "jsonpath={.status.phase}", check=False)


@pytest.fixture(scope="module")
def workloads(cluster: Cluster) -> Cluster:
    cluster.apply(string.Template((HERE / "workloads.yaml").read_text()).substitute(cluster.values))
    try:
        wait_for(lambda: WORKLOAD_ID in pod_logs(cluster, "with-identity"), 300,
                 "the labelled workload to receive its SVID", interval=3)  # fmt: skip
    except AssertionError:
        pytest.fail(f"{pod_logs(cluster, 'with-identity')}\n{cluster.diagnostics()}")
    return cluster


def test_agents_attest_with_service_account_tokens(cluster: Cluster) -> None:
    agents = cluster.server("agent", "list")
    assert "k8s_psat" in agents, agents
    assert "spiffe://example.org/spire/agent/k8s_psat/functest/" in agents


def test_csi_driver_registers_with_the_kubelet(cluster: Cluster) -> None:
    drivers = cluster.kubectl("get", "csinodes", "-o", "jsonpath={.items[*].spec.drivers[*].name}")
    assert "csi.spiffe.io" in drivers.split()


def test_controller_manager_creates_entries_from_cluster_spiffe_ids(workloads: Cluster) -> None:
    stats = json.loads(
        workloads.kubectl("get", "clusterspiffeid", "functest", "-o", "jsonpath={.status.stats}")
    )
    assert stats.get("entriesToSet", 0) >= 1, stats
    assert stats.get("entryFailures", 0) == 0, stats
    assert WORKLOAD_ID in workloads.server("entry", "show")


def test_labelled_pod_gets_its_spiffe_id_through_the_csi_volume(workloads: Cluster) -> None:
    out = pod_logs(workloads, "with-identity")
    assert f"SPIFFE ID:\t\t{WORKLOAD_ID}" in out, out


def test_unlabelled_pod_gets_no_identity(workloads: Cluster) -> None:
    docs = yaml.safe_load_all(
        string.Template((HERE / "workloads.yaml").read_text()).substitute(workloads.values)
    )
    template = next(d for d in docs if d and d["kind"] == "Pod")
    neg = copy.deepcopy(template)
    neg["metadata"]["name"] = "without-identity"
    del neg["metadata"]["labels"]
    workloads.apply(yaml.safe_dump(neg))
    wait_for(lambda: pod_phase(workloads, "without-identity") == "Running", 120, "the unlabelled pod to run")
    # The labelled pod got its SVID within seconds; give this one longer, then
    # check it was only ever refused.
    wait_for(lambda: pod_logs(workloads, "without-identity").count("no identity issued") >= 5, 120,
             "repeated refusals", interval=3)  # fmt: skip
    out = pod_logs(workloads, "without-identity")
    assert "SPIFFE ID" not in out, out
    assert "spiffe://" not in out, out
