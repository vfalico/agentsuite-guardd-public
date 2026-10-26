"""Opt-in real CRI + authenticated RPC + kernel enforcement on an owned lab Pod."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

from agentsuite_guardd.enforcement_protocol import requirement_digest
from agentsuite_guardd.kubernetes_provider import KubernetesEnforcementProvider
from agentsuite_guardd.kubernetes_target import KubernetesTargetResolver
from agentsuite_guardd.model import canonical
from agentsuite_guardd.native_filesystem import FilesystemNative
from agentsuite_guardd.neutral_service import Service
from orka_enforcement.v1 import enforcement_pb2 as wire
from test_enforcement_mtls import authenticated_channel


@pytest.fixture
def owned_kubernetes_container():
    config = os.environ.get("GUARDD_KUBERNETES_CONFIG")
    if not config or not os.environ.get("GUARDD_FILESYSTEM_OBJECT"):
        pytest.skip("explicit private Kubernetes config and native object required")
    if os.geteuid() != 0:
        pytest.fail("native Kubernetes qualification requires root")
    binary = shutil.which("kubectl")
    if not binary:
        pytest.fail("kubectl required for explicitly selected lab cluster")
    namespace = "guardd-native-" + uuid.uuid4().hex

    def kubectl(*args, value=None, check=True):
        return subprocess.run(
            [binary, "--kubeconfig", config, "--request-timeout=75s", *args],
            input=json.dumps(value).encode() if value is not None else None,
            capture_output=True, timeout=90, check=check,
        )

    nodes = json.loads(kubectl("get", "nodes", "-o", "json").stdout)["items"]
    machine_id = Path("/etc/machine-id").read_text().strip()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    local_nodes = [
        node for node in nodes
        if node["status"]["nodeInfo"]["machineID"] == machine_id
        and node["status"]["nodeInfo"]["bootID"] == boot_id
    ]
    assert len(local_nodes) == 1, "explicit lab cluster must contain exactly this native host"
    local_node = local_nodes[0]
    kubectl("create", "-f", "-", value=dict(
        apiVersion="v1", kind="Namespace", metadata=dict(name=namespace),
    ))
    try:
        kubectl("create", "-f", "-", value=dict(
            apiVersion="v1", kind="Pod", metadata=dict(name="worker", namespace=namespace),
            spec=dict(
                restartPolicy="Never", automountServiceAccountToken=False,
                nodeName=local_node["metadata"]["name"],
                containers=[dict(
                    name="worker", image="docker.io/library/busybox:1.36",
                    imagePullPolicy="IfNotPresent",
                    command=["/bin/sh", "-c",
                             "set -eu; printf original > /protected/canary; "
                             "mkfifo /tmp/hold; exec 3<>/tmp/hold; read -r value <&3"],
                    securityContext=dict(
                        runAsUser=0, runAsGroup=0, allowPrivilegeEscalation=False,
                        readOnlyRootFilesystem=True, capabilities=dict(drop=["ALL"]),
                        seccompProfile=dict(type="RuntimeDefault"),
                    ),
                    resources=dict(
                        requests=dict(cpu="50m", memory="32Mi"),
                        limits=dict(cpu="200m", memory="64Mi"),
                    ),
                    volumeMounts=[
                        dict(name="protected", mountPath="/protected"),
                        dict(name="temporary", mountPath="/tmp"),
                    ],
                )],
                volumes=[
                    dict(name="protected", emptyDir={}), dict(name="temporary", emptyDir={}),
                ],
            ),
        ))
        kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/worker", "--timeout=60s")
        pod = json.loads(kubectl("-n", namespace, "get", "pod", "worker", "-o", "json").stdout)
        node = json.loads(kubectl("get", "node", pod["spec"]["nodeName"], "-o", "json").stdout)
        facts = dict(
            nodeName=node["metadata"]["name"], nodeUID=node["metadata"]["uid"],
            namespace=namespace, podName="worker", podUID=pod["metadata"]["uid"],
            containerName="worker", containerID=pod["status"]["containerStatuses"][0]["containerID"],
        )
        yield kubectl, facts
    finally:
        kubectl("delete", "namespace", namespace, "--wait=true", "--timeout=60s")


def test_real_cri_rpc_root_denial_and_stopped_restart_retirement(tmp_path, owned_kubernetes_container):
    kubectl, facts = owned_kubernetes_container
    object_path = Path(os.environ["GUARDD_FILESYSTEM_OBJECT"]).resolve(strict=True)
    cri_binary = shutil.which("crictl")
    assert cri_binary, "trusted local CRI client required"
    resolver = KubernetesTargetResolver(facts["nodeName"], facts["nodeUID"], [cri_binary])
    pins = Path("/sys/fs/bpf") / ("guardd-kubernetes-" + uuid.uuid4().hex)
    database = tmp_path / "provider.db"
    policy = canonical(dict(
        version="agentsuite.policy/v1", denyWritePaths=["/protected"],
        requiredCapabilities=["filesystem/deny-write/v1"],
    ))
    request = wire.EnsureRequest(
        binding_id="k8s:" + hashlib.sha256(canonical(facts)).hexdigest(),
        requirement=wire.Requirement(
            format="agentsuite.policy/v1", policy=policy,
            required_capabilities=["filesystem/deny-write/v1"],
            mode=wire.Requirement.MODE_ENFORCE,
        ),
        target_facts=wire.TargetFacts(
            format="orka.kubernetes-container/v1", value=canonical(facts),
        ),
    )
    retirement = wire.RetireRequest(binding_id=request.binding_id)

    @contextmanager
    def provider():
        service = Service(database, pins, None, FilesystemNative(object_path))
        adapter = None
        try:
            adapter = KubernetesEnforcementProvider(
                service, resolver, ["spiffe://orka.ai/controller"],
            )
            with authenticated_channel(adapter, "spiffe://orka.ai/controller") as client:
                yield client
        finally:
            if adapter is not None:
                adapter.close()
            service.close()

    def execute(command, check=True):
        return kubectl("-n", facts["namespace"], "exec", "worker", "--",
                       "/bin/sh", "-c", command, check=check)

    # Identical root identity and writable volume before/after installation.
    execute("test -p /tmp/hold; printf baseline > /protected/canary; printf baseline > /tmp/allowed")
    try:
        with provider() as client:
            result = client.EnsureEnforced(request, timeout=30)
            assert result.HasField("enforced"), result
            assert result.enforced.requirement_digest == requirement_digest(request.requirement)
            assert result.enforced.evidence
            assert execute("printf forbidden > /protected/canary", check=False).returncode != 0
            assert execute("cat /protected/canary").stdout == b"baseline"
            execute("printf allowed > /tmp/allowed; test \"$(cat /tmp/allowed)\" = allowed")
            assert client.RetireEnforcement(retirement, timeout=30).HasField("pending")
        # Restart loses all original Python handles but must verify existing
        # populated-container controls, not reactivate a singleton bootstrap.
        with provider() as client:
            assert client.EnsureEnforced(request, timeout=30).HasField("enforced")
        kubectl("-n", facts["namespace"], "delete", "pod", "worker", "--wait=true", "--timeout=60s")
        # Another restart: stopped/absent CRI proof, not a retained cgroup FD.
        with provider() as client:
            assert client.RetireEnforcement(retirement, timeout=30).HasField("retired")
            assert client.EnsureEnforced(request, timeout=30).HasField("refused")
        assert not any(pins.iterdir())
    finally:
        kubectl("-n", facts["namespace"], "delete", "pod", "worker",
                "--ignore-not-found", "--wait=true", "--timeout=60s")
        with provider() as client:
            result = client.RetireEnforcement(retirement, timeout=30)
            assert result.HasField("retired"), result
        if not any(pins.iterdir()):
            pins.rmdir()
