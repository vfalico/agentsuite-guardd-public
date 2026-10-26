"""Qualified CRI identity/isolation behavior; no kernel claims."""
from unittest.mock import patch

import pytest

from agentsuite_guardd.kubernetes_target import (
    KubernetesTargetResolver, TargetPending, parse_facts, validate_cgroup_mounts, validate_inspection,
)
from agentsuite_guardd.model import canonical
from orka_enforcement.v1 import enforcement_pb2 as wire


def facts():
    return dict(
        nodeName="node", nodeUID="node-uid", namespace="tasks",
        podName="worker", podUID="pod-uid", containerName="worker",
        containerID="containerd://" + "a" * 64,
    )


def inspection():
    value = facts()
    return dict(
        status=dict(
            id="a" * 64, metadata=dict(name="worker"), state="CONTAINER_RUNNING",
            labels={
                "io.kubernetes.pod.uid": value["podUID"],
                "io.kubernetes.pod.name": value["podName"],
                "io.kubernetes.pod.namespace": value["namespace"],
                "io.kubernetes.container.name": value["containerName"],
            },
        ),
        info=dict(pid=123, runtimeSpec=dict(
            linux=dict(namespaces=[dict(type="pid"), dict(type="mount")]),
            process=dict(capabilities=dict(bounding=["CAP_SETUID", "CAP_SYS_CHROOT"])),
            mounts=[dict(destination="/sys/fs/cgroup", options=["ro"])],
        )),
    )


def test_exact_node_container_and_pod_are_independently_required():
    value = wire.TargetFacts(format="orka.kubernetes-container/v1", value=canonical(facts()))
    assert parse_facts(value, "node", "node-uid") == facts()
    assert validate_inspection(facts(), inspection()) == 123
    for name, uid in [("other", "node-uid"), ("node", "replacement-node")]:
        with pytest.raises(ValueError, match="node incarnation"):
            parse_facts(value, name, uid)
    modified = facts()
    modified["containerID"] = "containerd://abc"
    with pytest.raises(ValueError, match="full immutable"):
        parse_facts(wire.TargetFacts(format=value.format, value=canonical(modified)), "node", "node-uid")
    for label in ("io.kubernetes.pod.uid", "io.kubernetes.pod.namespace", "io.kubernetes.pod.name"):
        changed = inspection()
        changed["status"]["labels"][label] = "unrelated"
        with pytest.raises(ValueError, match="ownership mismatch"):
            validate_inspection(facts(), changed)


@pytest.mark.parametrize("change", [
    "host-pid", "shared-mount", "cgroup-write", "sys-admin", "bpf", "unknown-state", "different-container",
])
def test_unqualified_isolation_and_replaced_containers_refuse(change):
    value = inspection()
    if change == "host-pid":
        value["info"]["runtimeSpec"]["linux"]["namespaces"] = [dict(type="mount")]
    elif change == "shared-mount":
        value["info"]["runtimeSpec"]["linux"]["namespaces"][1]["path"] = "/proc/1/ns/mnt"
    elif change == "cgroup-write":
        value["info"]["runtimeSpec"]["mounts"][0]["options"] = ["rw"]
    elif change in {"sys-admin", "bpf"}:
        value["info"]["runtimeSpec"]["process"]["capabilities"]["ambient"] = [
            "CAP_SYS_ADMIN" if change == "sys-admin" else "CAP_BPF",
        ]
    elif change == "unknown-state":
        value["status"]["state"] = "CONTAINER_UNKNOWN"
    else:
        value["status"]["id"] = "b" * 64
    with pytest.raises(ValueError):
        validate_inspection(facts(), value)


@pytest.mark.parametrize("info", ["normal", "empty", "absent"])
@pytest.mark.parametrize("state", ["CONTAINER_CREATED", "CONTAINER_EXITED"])
def test_nonrunning_exact_incarnation_is_pending_not_enforced(info, state):
    value = inspection()
    value["status"]["state"] = state
    if info == "empty":
        value["info"] = {}
    elif info == "absent":
        del value["info"]
    with pytest.raises(TargetPending):
        validate_inspection(facts(), value)


@pytest.mark.parametrize("info", ["empty", "absent"])
def test_running_without_runtime_info_cannot_resolve_a_physical_target(info):
    value = inspection()
    if info == "empty":
        value["info"] = {}
    else:
        del value["info"]
    with pytest.raises(KeyError):
        validate_inspection(facts(), value)


@pytest.mark.parametrize("field", [
    "id", "name", "io.kubernetes.pod.uid", "io.kubernetes.pod.name",
    "io.kubernetes.pod.namespace", "io.kubernetes.container.name",
])
@pytest.mark.parametrize("state", ["CONTAINER_CREATED", "CONTAINER_EXITED"])
def test_nonrunning_without_info_still_requires_exact_container_ownership(field, state):
    value = inspection()
    value["status"]["state"] = state
    del value["info"]
    if field == "id":
        value["status"]["id"] = "b" * 64
    elif field == "name":
        value["status"]["metadata"]["name"] = "other"
    else:
        value["status"]["labels"][field] = "other"
    with pytest.raises(ValueError):
        validate_inspection(facts(), value)


def test_readonly_canonical_mount_does_not_hide_writable_alias():
    canonical_mount = "1 0 0:1 / /sys/fs/cgroup ro,nosuid - cgroup2 cgroup rw\n"
    alias = "2 0 0:1 / /host-cgroup rw,nosuid - cgroup2 cgroup rw\n"
    validate_cgroup_mounts(canonical_mount)
    validate_cgroup_mounts(canonical_mount + alias.replace(" rw,nosuid ", " ro,nosuid "))
    with pytest.raises(ValueError, match="including aliases"):
        validate_cgroup_mounts(canonical_mount + alias)


def test_only_successful_exact_runtime_inventory_proves_stop(tmp_path):
    resolver = KubernetesTargetResolver("node", "node-uid", ["/usr/bin/crictl"])
    with patch.object(resolver, "cri", return_value={"containers": []}):
        assert resolver.stopped(facts())[0]
    with patch.object(resolver, "cri", return_value={
        "containers": [dict(id="a" * 64, state="CONTAINER_RUNNING")],
    }):
        assert not resolver.stopped(facts())[0]
    with patch.object(resolver, "cri", side_effect=RuntimeError("socket disconnected")):
        with pytest.raises(RuntimeError):
            resolver.stopped(facts())
    with patch.object(resolver, "cri", return_value={}):
        with pytest.raises(RuntimeError, match="complete container inventory"):
            resolver.stopped(facts())
