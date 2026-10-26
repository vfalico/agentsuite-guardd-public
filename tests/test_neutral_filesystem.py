"""Filesystem dispatch/lifecycle with explicit non-kernel recording backends."""
import base64
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from agentsuite_guardd.model import canonical, policy_digest
from agentsuite_guardd.native_filesystem import HeldPaths, FilesystemNative
from agentsuite_guardd.neutral_service import Service, requirement, validate_config, same_cgroup_object
from agentsuite_guardd.policy import BackendPlan, OPERATIONS


def envelope(paths):
    raw = canonical(dict(version="agentsuite.policy/v1", denyWritePaths=paths,
                         requiredCapabilities=["filesystem/deny-write/v1"]))
    return dict(format="agentsuite.policy/v1", bytes=base64.b64encode(raw).decode(),
                digest=policy_digest(raw), capabilities=["filesystem/deny-write/v1"])


class RecordingNative:
    PROGRAMS = FilesystemNative.PROGRAMS
    MAPS = FilesystemNative.MAPS

    def __init__(self):
        self.installs = []
        self.fail = False

    def install(self, directory, fd, spec):
        self.installs.append(spec)
        Path(directory).mkdir()
        if self.fail:
            raise RuntimeError("partial install")
        return self.verify(directory, fd, spec)

    def verify(self, directory, fd, spec):
        return dict(filesystem=spec, maps={}, links={}, programs={})


@pytest.fixture
def context(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "canary").write_text("original")
    start = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
    target = dict(boot="test", cgroup=dict(dev=1, ino=2), pid=42, start=start,
                  netns=7, generation=3)
    req = dict(version="execution-enforcement/v1", method="activate", operation="fs",
               requirement=envelope([str(protected)]), target=target)
    network, filesystem = RecordingNative(), RecordingNative()
    service = Service(tmp_path / "state", tmp_path / "pins", network, filesystem)
    with patch("agentsuite_guardd.neutral_service.held_target", return_value=os.getpid()), \
         patch("agentsuite_guardd.neutral_service.boot_id", return_value="test"), \
         patch("agentsuite_guardd.neutral_service.target_identity", return_value=dict(boot="test", cgroup=target["cgroup"])), \
         patch("agentsuite_guardd.neutral_service.cgroup_removed", return_value=False), \
         patch("agentsuite_guardd.neutral_service.task_ids", return_value=[os.getpid()]), \
         patch("agentsuite_guardd.neutral_service.read_events", return_value=dict(populated=0)):
        yield service, req, protected
    service.close()


def test_dispatch_reuses_filesystem_compiler():
    plan = requirement(envelope(["/protected"]))
    assert isinstance(plan, BackendPlan)
    assert plan.deny_write_paths == ("/protected",)
    assert plan.operation_set == OPERATIONS
    for mutation in [dict(capabilities=[]), dict(capabilities=["filesystem/deny-write/v1", "network/egress-allow/v1"]),
                     dict(format="agentsuite.policy/v2"), dict(digest="sha256:" + "0" * 64)]:
        with pytest.raises(ValueError):
            requirement(dict(envelope(["/protected"]), **mutation))


def test_optional_config_preserves_network_contract():
    config = dict(socket="/socket", state="/state", pins="/pins", object="/network.bpf.o")
    validate_config(config)
    validate_config(dict(config, filesystemObject="/filesystem.bpf.o"))
    for mutation in [dict(filesystemObject="relative"), dict(unknown="/unknown"), dict(filesystemObject=None)]:
        with pytest.raises(ValueError):
            validate_config(dict(config, **mutation))


def test_support_requires_explicit_filesystem_object(context):
    service, req, _ = context
    req = dict(req, method="assess", operation="", target=None)
    assert service.dispatch(req, []) == dict(supported=True)
    service.filesystem = None
    assert not service.dispatch(req, [])["supported"]
    assert not service.native.installs


@pytest.mark.parametrize("kind", ["cgroup-subtree/v1", "network-interface/v1", "invented/v1"])
def test_filesystem_rejects_non_held_targets_before_binding(context, kind):
    service, req, _ = context
    req["target"] = dict(req["target"], kind=kind)
    with pytest.raises(ValueError, match="held-native"):
        service.dispatch(req, [1, 2, 3])
    assert service.row("fs") is None
    assert service.filesystem.installs == []


def test_activation_uses_authenticated_receiver_pid_not_caller_pid(context):
    service, req, _ = context
    assert req["target"]["pid"] != os.getpid()
    assert service.dispatch(req, [1, 2, 3])["active"]
    spec = service.filesystem.installs[0]
    assert spec["pid"] == os.getpid()
    assert spec["generation"] == req["target"]["generation"]
    assert service.native.installs == []
    assert service.dispatch(req, [1, 2, 3])["active"]
    assert len(service.filesystem.installs) == 1
    readback = service.dispatch(dict(req, method="lookup"), [1])
    assert readback["active"]
    assert readback["readback"]["filesystem"] == spec
    assert readback["operation"] == "fs"
    with patch.object(service.filesystem, "verify", side_effect=ValueError("kernel mismatch")):
        with pytest.raises(ValueError, match="kernel mismatch"):
            service.dispatch(dict(req, method="lookup"), [1])
    assert service.row("fs")[2] == "ACTIVE"
    changed = dict(req, requirement=envelope(["/different"]))
    with pytest.raises(ValueError, match="cannot change"):
        service.dispatch(changed, [1, 2, 3])


def test_changed_path_blocks_retry_and_lookup_without_removing_restrictions(context):
    service, req, protected = context
    service.dispatch(req, [1, 2, 3])
    (protected / "canary").unlink()
    (protected / "canary").write_text("new")
    for method, fds in [("activate", [1, 2, 3]), ("lookup", [1])]:
        with pytest.raises(ValueError, match="identit"):
            service.dispatch(dict(req, method=method), fds)
    assert service.row("fs")[2] == "ACTIVE"
    assert len(service.filesystem.installs) == 1


def test_retiring_unknown_binding_tombstones_delayed_activation(context):
    service, req, _ = context
    with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
        assert service.dispatch(dict(req, method="retire"), [1])["retired"]
        assert service.dispatch(dict(req, method="retire"), [1])["retired"]
    assert service.row(req["operation"])[2] == "RETIRED"
    with pytest.raises(ValueError, match="cleanup-only"):
        service.dispatch(req, [1, 2, 3])
    assert not service.filesystem.installs


def test_oversized_snapshot_refuses_before_installation(context):
    service, req, _ = context
    with pytest.raises(ValueError, match="transport reply capacity"):
        service.dispatch(req, [1, 2, 3], reply_limit=256)
    assert not service.filesystem.installs
    assert service.row(req["operation"]) is None
    assert not service.held_paths


def test_complete_kernel_readback_must_fit_before_active(context):
    service, req, _ = context
    original = service.filesystem.verify
    with patch.object(
        service.filesystem, "verify",
        side_effect=lambda *args: dict(original(*args), extra="x" * 16384),
    ):
        with pytest.raises(ValueError, match="transport reply capacity"):
            service.dispatch(req, [1, 2, 3], reply_limit=4096)
    assert len(service.filesystem.installs) == 1
    assert service.row(req["operation"])[2] == "ACTIVATING"
    with pytest.raises(ValueError, match="cleanup-only"):
        service.dispatch(req, [1, 2, 3])


def test_filesystem_uncertain_install_is_cleanup_only_and_needs_stable_empty(context):
    service, req, _ = context
    service.filesystem.fail = True
    with pytest.raises(RuntimeError, match="partial"):
        service.dispatch(req, [1, 2, 3])
    assert service.row("fs")[2] == "ACTIVATING"
    assert json.loads(service.row("fs")[3])["filesystem"]["pid"] == os.getpid()
    with pytest.raises(ValueError, match="cleanup-only"):
        service.dispatch(req, [1, 2, 3])
    assert not service.dispatch(dict(req, method="lookup"), [1])["active"]
    with pytest.raises(ValueError, match="runtime-stopped"):
        service.dispatch(dict(req, method="retire"), [1])
    assert service.row("fs")[2] == "ACTIVATING"
    with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
        assert service.dispatch(dict(req, method="retire"), [1])["retired"]
    assert service.row("fs")[2] == "RETIRED"
    assert "fs" not in service.held_paths


def test_restart_recovers_exact_snapshot_without_reinstall(context):
    service, req, _ = context
    service.dispatch(req, [1, 2, 3])
    filesystem, native = service.filesystem, service.native
    state, pins = service.state, service.pins
    service.close()
    recovered = Service(state, pins, native, filesystem)
    try:
        assert recovered.dispatch(dict(req, method="lookup"), [1])["active"]
        assert "fs" in recovered.held_paths
        with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
            with pytest.raises(ValueError, match="no longer belongs"):
                recovered.dispatch(dict(req, method="lookup"), [1])
        assert len(filesystem.installs) == 1
    finally:
        recovered.close()
        # Restore the fixture's owned connection for its normal finalizer.
        service.__init__(state, pins, native, filesystem)


def test_readback_failure_keeps_durable_ownership_and_restrictions(context):
    service, req, _ = context
    original_verify = service.filesystem.verify
    calls = 0

    def verify(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("readback fault")
        return original_verify(*args)

    with patch.object(service.filesystem, "verify", side_effect=verify):
        with pytest.raises(ValueError, match="readback fault"):
            service.dispatch(req, [1, 2, 3])
    row = service.row("fs")
    assert row[2] == "ACTIVATING"
    assert json.loads(row[3])["filesystem"]
    assert Path(row[4]).is_dir()
    assert "fs" in service.held_paths


def test_uncertain_partial_inventory_is_journaled_and_absence_required(context):
    service, req, _ = context
    service.filesystem.fail = True
    with pytest.raises(RuntimeError):
        service.dispatch(req, [1, 2, 3])
    pin = Path(service.row("fs")[4]) / "guarded_paths"
    pin.touch()
    with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]), \
         patch.object(service.filesystem, "info", return_value={"id": 80}, create=True), \
         patch.object(service.filesystem, "object_exists", return_value=True, create=True), \
         patch("agentsuite_guardd.neutral_service.time.monotonic", side_effect=[0, 6]):
        with pytest.raises(ValueError, match="residue remains"):
            service.dispatch(dict(req, method="retire"), [1])
    row = service.row("fs")
    assert row[2] == "EMPTY_CONFIRMED"
    assert json.loads(row[3])["maps"]["guarded_paths"]["id"] == 80
    assert "fs" in service.held_paths
    assert not pin.exists()
    with patch.object(service.filesystem, "object_exists", return_value=False, create=True) as absent:
        assert service.dispatch(dict(req, method="retire"), [])["retired"]
        absent.assert_called_once_with("map", 80)
    assert "fs" not in service.held_paths


def test_unknown_pin_blocks_even_stopped_partial_cleanup(context):
    service, req, _ = context
    service.filesystem.fail = True
    with pytest.raises(RuntimeError):
        service.dispatch(req, [1, 2, 3])
    pin = Path(service.row("fs")[4]) / "foreign"
    pin.touch()
    with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
        with pytest.raises(ValueError, match="foreign pin"):
            service.dispatch(dict(req, method="retire"), [1])
    assert pin.exists()
    assert service.row("fs")[2] == "EMPTY_CONFIRMED"


@pytest.mark.parametrize("malformed", [
    None, [], {}, {"format": "agentsuite.policy/v1"},
    {"format": "agentsuite.policy/v2", "bytes": "", "digest": "invalid",
     "capabilities": ["network/egress-allow/v1"]},
])
def test_malformed_or_cross_policy_replay_never_changes_operation(context, malformed):
    service, req, _ = context
    service.dispatch(req, [1, 2, 3])
    before = service.row("fs")
    for method in ["activate", "lookup", "retire"]:
        with pytest.raises(ValueError):
            service.dispatch(dict(req, method=method, requirement=malformed), [1, 2, 3])
        assert service.row("fs") == before
    assert len(service.filesystem.installs) == 1
    assert not service.native.installs


@pytest.mark.parametrize("uncertain", [False, True])
def test_restart_cleanup_after_actor_death_uses_durably_bound_backend(context, uncertain):
    service, req, _ = context
    service.filesystem.fail = uncertain
    if uncertain:
        with pytest.raises(RuntimeError):
            service.dispatch(req, [1, 2, 3])
    else:
        service.dispatch(req, [1, 2, 3])
        proof = json.loads(service.row("fs")[3])
        proof["maps"]["guarded_paths"] = {"id": 81}
        service.update("fs", "ACTIVE", proof)
    (Path(service.row("fs")[4]) / "guarded_paths").touch()
    state, pins, native, filesystem = service.state, service.pins, service.native, service.filesystem
    service.close()
    recovered = Service(state, pins, native, filesystem)
    try:
        with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]), \
             patch("agentsuite_guardd.neutral_service.HeldPaths", side_effect=AssertionError("dead actor root must not be needed")), \
             patch("agentsuite_guardd.neutral_service.held_target", side_effect=ProcessLookupError("actor died")), \
             patch.object(native, "info", side_effect=AssertionError("wrong backend"), create=True), \
             patch.object(native, "object_exists", side_effect=AssertionError("wrong backend"), create=True), \
             patch.object(filesystem, "info", return_value={"id": 81}, create=True), \
             patch.object(filesystem, "object_exists", return_value=False, create=True) as absent:
            assert recovered.dispatch(dict(req, method="retire"), [1])["retired"]
            absent.assert_called_once_with("map", 81)
        assert recovered.row("fs")[2] == "RETIRED"
        assert json.loads(recovered.row("fs")[3])["filesystem"]["pid"] == os.getpid()
    finally:
        recovered.close()
        service.__init__(state, pins, native, filesystem)


@pytest.mark.parametrize("field", ["none", "boot", "dev", "ino", "cgroup_id", "mount_id", "missing"])
def test_cross_mount_cgroup_identity_is_not_a_different_object(field):
    expected = dict(boot="boot", cgroup=dict(dev=31, ino=7514292, cgroup_id=7514292, mount_id=3090))
    actual = dict(boot="boot", cgroup=dict(expected["cgroup"], mount_id=37))
    if field == "boot":
        actual["boot"] = "different-boot"
    elif field == "mount_id":
        actual["cgroup"]["mount_id"] = 0
    elif field == "missing":
        del actual["cgroup"]["cgroup_id"]
    elif field != "none":
        actual["cgroup"][field] += 1
    assert same_cgroup_object(actual, expected) is (field == "none")


def test_filesystem_lookup_accepts_only_descriptor_mount_alias_not_changed_root(context):
    service, req, protected = context
    req["target"]["cgroup"] = dict(dev=31, ino=42, cgroup_id=42, mount_id=3090)
    service.dispatch(req, [1, 2, 3])
    actual = dict(boot="test", cgroup=dict(req["target"]["cgroup"], mount_id=37))
    with patch("agentsuite_guardd.neutral_service.target_identity", return_value=actual):
        assert service.dispatch(dict(req, method="lookup"), [1])["active"]
        changed = json.loads(json.dumps(req))
        changed["target"]["cgroup"]["mount_id"] = 37
        with pytest.raises(ValueError, match="cannot change"):
            service.dispatch(dict(changed, method="lookup"), [1])
        with pytest.raises(ValueError, match="exact target changed"):
            service.dispatch(dict(req, method="retire"), [1])
        with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
            with pytest.raises(ValueError, match="no longer belongs"):
                service.dispatch(dict(req, method="lookup"), [1])
        (protected / "canary").unlink()
        (protected / "canary").write_text("replacement")
        with pytest.raises(ValueError, match="identities changed"):
            service.dispatch(dict(req, method="lookup"), [1])
    assert service.row("fs")[2] == "ACTIVE"
