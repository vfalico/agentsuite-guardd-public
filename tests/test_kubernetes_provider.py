"""Provider lifecycle with recording kernel/CRI seams; not native qualification."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import grpc

from agentsuite_guardd.kubernetes_provider import KubernetesEnforcementProvider
from agentsuite_guardd.kubernetes_target import KubernetesTargetResolver, ResolvedContainer, TargetPending
from agentsuite_guardd.model import canonical
from agentsuite_guardd.neutral_service import Service, TargetNotLive, pidfd_identity
from orka_enforcement.v1 import enforcement_pb2 as wire
from test_neutral_filesystem import RecordingNative


class RecordingResolver:
    def __init__(self, facts, target, directory):
        self.value, self.target = facts, target
        self.cgroup_root = directory
        self.is_stopped = False
        self.stop_calls = 0

    @contextmanager
    def resolve(self, _value):
        descriptor = os.pidfd_open(os.getpid())
        try:
            yield ResolvedContainer(self.value, self.target, "/removed-container", (1, descriptor, 3))
        finally:
            os.close(descriptor)

    def stopped(self, _facts):
        self.stop_calls += 1
        return self.is_stopped, {"containers": []}


@pytest.fixture
def provider_context(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "canary").write_text("original")
    target = dict(
        boot="test-boot", cgroup=dict(dev=1, ino=2, mount_id=3, cgroup_id=2),
        pid=os.getpid(),
        start=Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19],
        netns=7, generation=1,
    )
    facts = dict(
        nodeName="node", nodeUID="node-uid", namespace="tasks",
        podName="worker", podUID="pod-uid", containerName="worker",
        containerID="containerd://" + "a" * 64,
    )
    policy = canonical(dict(
        version="agentsuite.policy/v1", denyWritePaths=[str(protected)],
        requiredCapabilities=["filesystem/deny-write/v1"],
    ))
    request = wire.EnsureRequest(
        binding_id="container-1",
        requirement=wire.Requirement(
            format="agentsuite.policy/v1", policy=policy,
            required_capabilities=["filesystem/deny-write/v1"],
            mode=wire.Requirement.MODE_ENFORCE,
        ),
        target_facts=wire.TargetFacts(format="orka.kubernetes-container/v1", value=canonical(facts)),
    )
    backend = RecordingNative()
    service = Service(tmp_path / "state", tmp_path / "pins", None, backend)
    resolver = RecordingResolver(facts, target, tmp_path)
    provider = KubernetesEnforcementProvider(service, resolver, ["spiffe://orka.ai/controller"])
    with patch("agentsuite_guardd.neutral_service.held_target", return_value=os.getpid()), \
         patch("agentsuite_guardd.neutral_service.boot_id", return_value="test-boot"), \
         patch("agentsuite_guardd.kubernetes_provider.boot_id", return_value="test-boot"), \
         patch("agentsuite_guardd.neutral_service.target_identity",
               return_value={key: target[key] for key in ("boot", "cgroup")}), \
         patch("agentsuite_guardd.neutral_service.cgroup_removed", return_value=False), \
         patch("agentsuite_guardd.neutral_service.task_ids", return_value=[os.getpid()]), \
         patch("agentsuite_guardd.neutral_service.read_events", return_value=dict(populated=0)):
        try:
            yield provider, request, backend, resolver
        finally:
            provider.close()
            service.close()


def test_populated_ensure_verifies_without_reactivation(provider_context):
    provider, request, backend, _ = provider_context
    assert provider.ensure(request).HasField("enforced")
    with patch("agentsuite_guardd.neutral_service.held_target", side_effect=AssertionError("reactivation")), \
         patch("agentsuite_guardd.neutral_service.task_ids", return_value=[os.getpid(), os.getpid() + 1]):
        assert provider.ensure(request).HasField("enforced")
    assert len(backend.installs) == 1


@pytest.mark.parametrize("operation", ["ensure", "retire"])
def test_refusal_diagnostic_preserves_outcome_without_logging_payload(provider_context, caplog, operation):
    provider, request, _, _ = provider_context
    context = SimpleNamespace(auth_context=lambda: {
        "x509_subject_alternative_name": [b"spiffe://orka.ai/controller"],
    })
    secret = "private-policy-or-credential"
    with patch.object(provider, operation, side_effect=ValueError(secret)):
        response = (
            provider.EnsureEnforced(request, context) if operation == "ensure"
            else provider.RetireEnforcement(wire.RetireRequest(binding_id=request.binding_id), context)
        )
    assert response.refused.reason == secret
    assert request.binding_id in caplog.text
    assert "ValueError" in caplog.text
    assert secret not in caplog.text
    assert request.requirement.policy.decode() not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("retained", [False, True])
def test_exact_exited_container_is_pending_without_activation_or_cleanup(provider_context, retained):
    provider, request, backend, resolver = provider_context
    if retained:
        provider.ensure(request)
    before = provider.row(request.binding_id)
    facts = resolver.value
    inspection = {"status": {
        "id": facts["containerID"].removeprefix("containerd://"),
        "metadata": {"name": facts["containerName"]},
        "state": "CONTAINER_EXITED",
        "labels": {
            "io.kubernetes.pod.uid": facts["podUID"],
            "io.kubernetes.pod.name": facts["podName"],
            "io.kubernetes.pod.namespace": facts["namespace"],
            "io.kubernetes.container.name": facts["containerName"],
        },
    }}
    provider.resolver = KubernetesTargetResolver("node", "node-uid", ["/usr/bin/crictl"])
    context = SimpleNamespace(auth_context=lambda: {
        "x509_subject_alternative_name": [b"spiffe://orka.ai/controller"],
    })
    with patch.object(provider.resolver, "cri", return_value=inspection):
        response = provider.EnsureEnforced(request, context)
    assert response.HasField("pending")
    assert provider.row(request.binding_id) == before
    assert len(backend.installs) == int(retained)


@contextmanager
def child_incarnation(resolver):
    process = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
    descriptor = os.pidfd_open(process.pid)

    @contextmanager
    def resolve(_facts):
        yield ResolvedContainer(resolver.value, resolver.target, "/removed-container", (1, descriptor, 3))

    try:
        with patch.object(resolver, "resolve", side_effect=resolve):
            yield process, descriptor
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdin.close()
        os.close(descriptor)


@pytest.mark.parametrize("reaped", [False, True])
@pytest.mark.parametrize("boundary", [
    "already-exited", "native-readback", "successful-readback", "integrity-error", "live-lifetime-error",
])
def test_kernel_exit_during_ensure_never_becomes_configuration_refusal(provider_context, boundary, reaped):
    provider, request, backend, resolver = provider_context
    if boundary != "already-exited":
        provider.ensure(request)
    before = provider.row(request.binding_id)
    installs = len(backend.installs)
    dispatch = provider.service.dispatch
    context = SimpleNamespace(auth_context=lambda: {
        "x509_subject_alternative_name": [b"spiffe://orka.ai/controller"],
    })
    with child_incarnation(resolver) as (process, descriptor):
        def stop():
            process.kill()
            if reaped:
                process.wait()
            else:
                os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)

        def observe(native_request, fds):
            result = dispatch(native_request, fds)
            if native_request["method"] == "lookup":
                if boundary == "live-lifetime-error":
                    raise TargetNotLive("filesystem root process left target during readback")
                stop()
                if boundary == "native-readback":
                    pidfd_identity(descriptor)
                elif boundary == "integrity-error":
                    raise ValueError("native policy-map ownership changed")
            return result

        if boundary == "already-exited":
            stop()
        with patch.object(provider.service, "dispatch", side_effect=observe):
            response = provider.EnsureEnforced(request, context)
        assert response.HasField("refused" if boundary in {"integrity-error", "live-lifetime-error"} else "pending")
        if before is not None and response.HasField("pending"):
            with pytest.raises(TargetPending):
                provider.retire(wire.RetireRequest(binding_id=request.binding_id))
            assert provider.service.row(request.binding_id)[2] == "ACTIVE"
    assert provider.row(request.binding_id) == before
    assert len(backend.installs) == installs


def test_uncertain_pidfd_observation_never_admits_or_retires(provider_context):
    provider, request, backend, _ = provider_context
    aborted = []

    def abort(code, _detail):
        aborted.append(code)
        raise RuntimeError("RPC aborted")

    context = SimpleNamespace(auth_context=lambda: {
        "x509_subject_alternative_name": [b"spiffe://orka.ai/controller"],
    }, abort=abort)
    poller = SimpleNamespace(register=lambda *_: None, poll=lambda _: [(123, select.POLLNVAL)])
    with patch("agentsuite_guardd.kubernetes_target.select.poll", return_value=poller):
        with pytest.raises(RuntimeError, match="RPC aborted"):
            provider.EnsureEnforced(request, context)
    assert aborted == [grpc.StatusCode.UNAVAILABLE]
    assert provider.row(request.binding_id) is None
    assert not backend.installs


@pytest.mark.parametrize(
    ("change", "need"),
    [
        ("unsupported-format", "supported-format"),
        ("missing-backend", "configured-backend"),
        ("invalid-policy", "complete-policy"),
    ],
)
def test_refusal_preserves_actionable_needs_without_partial_activation(provider_context, change, need):
    provider, request, backend, _ = provider_context
    if change == "unsupported-format":
        request.requirement.format = "unsupported.policy/v1"
    elif change == "missing-backend":
        request.requirement.format = "agentsuite.policy/v3"
    else:
        request.requirement.policy = b"private-invalid-policy"
    context = SimpleNamespace(auth_context=lambda: {
        "x509_subject_alternative_name": [b"spiffe://orka.ai/controller"],
    })
    result = provider.EnsureEnforced(request, context)
    assert result.HasField("refused")
    assert need in result.refused.needs
    assert not backend.installs
    assert provider.row(request.binding_id) is None


def test_binding_cannot_change_policy_or_incarnation(provider_context):
    provider, request, backend, resolver = provider_context
    provider.ensure(request)
    changed = wire.EnsureRequest()
    changed.CopyFrom(request)
    changed.target_facts.value += b" "
    with pytest.raises(ValueError, match="cannot change"):
        provider.ensure(changed)
    resolver.target = dict(resolver.target, start="different-start")
    with pytest.raises(ValueError, match="incarnation changed"):
        provider.ensure(request)
    assert len(backend.installs) == 1


def test_retirement_waits_for_container_not_one_consumer(provider_context):
    provider, request, backend, _ = provider_context
    provider.ensure(request)
    retirement = wire.RetireRequest(binding_id=request.binding_id)
    with pytest.raises(TargetPending, match="stop the physical container"):
        provider.retire(retirement)
    assert provider.service.row(request.binding_id)[2] == "ACTIVE"
    with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
        assert provider.retire(retirement).retired.binding_id == request.binding_id
    assert provider.retire(retirement).retired.binding_id == request.binding_id
    with pytest.raises(ValueError, match="cleanup-only"):
        provider.ensure(request)
    assert len(backend.installs) == 1


def test_unknown_retirement_tombstones_delayed_ensure(provider_context):
    provider, request, backend, _ = provider_context
    provider.retire(wire.RetireRequest(binding_id=request.binding_id))
    with pytest.raises(ValueError, match="cleanup-only"):
        provider.ensure(request)
    assert not backend.installs


def test_lost_handle_requires_positive_runtime_stop_proof(provider_context):
    provider, request, _, resolver = provider_context
    provider.ensure(request)
    provider.close()
    retirement = wire.RetireRequest(binding_id=request.binding_id)
    with pytest.raises(TargetPending):
        provider.retire(retirement)
    resolver.is_stopped = True
    assert provider.retire(retirement).HasField("retired")
    assert resolver.stop_calls == 2
    proof = provider.service.db.execute(
        "SELECT stop_proof FROM provider_bindings WHERE binding=?", (request.binding_id,),
    ).fetchone()[0]
    assert json.loads(proof) == {"containers": []}


def test_lost_handle_runtime_failure_never_authorizes_cleanup(provider_context):
    provider, request, _, resolver = provider_context
    provider.ensure(request)
    provider.close()
    with patch.object(resolver, "stopped", side_effect=RuntimeError("CRI unavailable")):
        with pytest.raises(RuntimeError, match="CRI unavailable"):
            provider.retire(wire.RetireRequest(binding_id=request.binding_id))
    assert provider.service.row(request.binding_id)[2] == "ACTIVE"


def test_previous_kernel_cleanup_does_not_inspect_reused_object_ids(provider_context):
    provider, request, _, _ = provider_context
    provider.ensure(request)
    provider.close()
    service = provider.service
    pins = Path(service.row(request.binding_id)[4])
    retirement = wire.RetireRequest(binding_id=request.binding_id)
    with patch("agentsuite_guardd.neutral_service.boot_id", return_value="new-kernel"), \
         patch("agentsuite_guardd.kubernetes_provider.boot_id", return_value="new-kernel"):
        with pytest.raises(ValueError, match="current pin ownership"):
            provider.retire(retirement)
        pins.rmdir()
        with patch.object(service, "remove", side_effect=AssertionError("old numeric object IDs")):
            assert provider.retire(retirement).HasField("retired")


@pytest.mark.parametrize("changed", ["mount_id", "ino", "dev", "cgroup_id", "boot"])
def test_stopped_recovery_accepts_only_mount_alias_not_another_kernel_target(provider_context, changed):
    provider, request, _, resolver = provider_context
    provider.ensure(request)
    provider.close()
    resolver.is_stopped = True
    (resolver.cgroup_root / "removed-container").mkdir()
    actual = json.loads(canonical({key: resolver.target[key] for key in ("boot", "cgroup")}))
    if changed == "boot":
        actual["boot"] = "other-boot"
    else:
        actual["cgroup"][changed] += 1
    retirement = wire.RetireRequest(binding_id=request.binding_id)
    with patch("agentsuite_guardd.neutral_service.target_identity", return_value=actual), \
         patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
        if changed == "mount_id":
            native_request = json.loads(provider.row(request.binding_id)[1])
            with pytest.raises(ValueError, match="exact target changed"):
                provider.service.dispatch(dict(native_request, method="retire"), [1])
            assert provider.retire(retirement).HasField("retired")
        else:
            with pytest.raises(ValueError, match="exact target changed"):
                provider.retire(retirement)
