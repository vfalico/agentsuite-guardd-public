import base64
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agentsuite_guardd.container_policy import FORMAT, ContainerPlan, compile_container
from agentsuite_guardd.model import canonical, policy_digest
from agentsuite_guardd.native_container import ContainerNative
from agentsuite_guardd.native_filesystem import FilesystemNative
from agentsuite_guardd.native_network import Native
from agentsuite_guardd.neutral_service import requirement
from test_neutral_filesystem import context


CAPABILITIES = ["filesystem/deny-write/v1", "network/egress-allow/v1"]


def policy(paths=None):
    return dict(
        version=FORMAT, denyWritePaths=paths or ["/protected"],
        requiredCapabilities=CAPABILITIES.copy(),
        network=dict(egressAllow=[
            dict(address="10.0.0.2", port=443, protocol="TCP"),
            dict(address="10.0.0.53", port=53, protocol="UDP"),
            dict(address="10.0.0.3", port="*", protocol="TCP"),
        ]),
    )


def envelope(value):
    raw = canonical(value)
    return dict(format=FORMAT, bytes=base64.b64encode(raw).decode(),
                digest=policy_digest(raw), capabilities=value["requiredCapabilities"])


def test_complete_compilation_preserves_identity_and_explicit_tuple_semantics():
    value = policy()
    original = copy.deepcopy(value)
    plan = requirement(envelope(value))
    assert isinstance(plan, ContainerPlan)
    assert plan.endpoints == (("10.0.0.2", 443, 6), ("10.0.0.53", 53, 17),
                              ("10.0.0.3", 0, 6))
    assert plan.deny_write_paths == ("/protected",)
    assert value == original
    value["requiredCapabilities"].reverse()
    assert requirement(envelope(value)).endpoints == plan.endpoints
    raw = canonical(value)
    with pytest.raises(ValueError, match="ordered capabilities"):
        compile_container(raw, policy_digest(raw), CAPABILITIES)
    value["network"]["egressAllow"] = []
    assert requirement(envelope(value)).endpoints == ()


@pytest.mark.parametrize("change", [
    lambda p: p.update(extra=True),
    lambda p: p.update(version="agentsuite.policy/v2"),
    lambda p: p.update(denyWritePaths=["/"]),
    lambda p: p.update(denyWritePaths=["relative"]),
    lambda p: p.update(denyWritePaths=["/z", "/a"]),
    lambda p: p.update(denyWritePaths=["/a", "/a"]),
    lambda p: p.update(requiredCapabilities=CAPABILITIES[:1]),
    lambda p: p.update(requiredCapabilities=CAPABILITIES + [CAPABILITIES[0]]),
    lambda p: p["network"].update(implicitRuntimeTraffic=True),
    lambda p: p["network"]["egressAllow"][0].update(address="example.com"),
    lambda p: p["network"]["egressAllow"][0].update(address="::1"),
    lambda p: p["network"]["egressAllow"][0].update(address="0.0.0.0"),
    lambda p: p["network"]["egressAllow"][0].update(address="255.255.255.255"),
    lambda p: p["network"]["egressAllow"][0].update(address="224.0.0.1"),
    lambda p: p["network"]["egressAllow"][0].update(port=True),
    lambda p: p["network"]["egressAllow"][0].update(port=0),
    lambda p: p["network"]["egressAllow"][0].update(port="443"),
    lambda p: p["network"]["egressAllow"][0].update(protocol="ICMP"),
    lambda p: p["network"]["egressAllow"][0].update(replyExemption=True),
    lambda p: p["network"]["egressAllow"].append(p["network"]["egressAllow"][0].copy()),
])
def test_incomplete_or_unsupported_policy_never_compiles(change):
    value = policy()
    change(value)
    with pytest.raises(ValueError):
        requirement(envelope(value))


def test_no_normalization_or_digest_substitution():
    raw = canonical(policy())
    for changed in (raw + b"\n", raw.replace(b'"version":', b'"version":"extra","version":')):
        with pytest.raises(ValueError):
            compile_container(changed, policy_digest(changed), CAPABILITIES)
    with pytest.raises(ValueError, match="digest"):
        compile_container(raw, "sha256:" + "0" * 64, CAPABILITIES)


def combined_context(context):
    service, request, protected = context
    service.container = service.filesystem
    request["requirement"] = envelope(policy([str(protected)]))
    return service, request, protected


def test_combined_binding_has_one_complete_install_and_current_recovery(context):
    service, request, _ = combined_context(context)
    assert service.dispatch(request, [1, 2, 3])["active"]
    assert len(service.container.installs) == 1
    spec = service.container.installs[0]
    assert spec["network"] == [["10.0.0.2", 443, 6], ["10.0.0.53", 53, 17],
                                ["10.0.0.3", 0, 6]]
    assert service.dispatch(request, [1, 2, 3])["active"]
    assert service.dispatch(dict(request, method="lookup"), [1])["readback"]["filesystem"] == spec
    with patch.object(service.container, "verify", side_effect=ValueError("network map changed")):
        with pytest.raises(ValueError, match="network map changed"):
            service.dispatch(dict(request, method="lookup"), [1])
    assert len(service.container.installs) == 1
    assert service.native.installs == []


def test_combined_partial_install_is_never_usable_or_removed_while_live(context):
    service, request, _ = combined_context(context)
    service.container.fail = True
    with pytest.raises(RuntimeError, match="partial install"):
        service.dispatch(request, [1, 2, 3])
    assert service.row(request["operation"])[2] == "ACTIVATING"
    assert json.loads(service.row(request["operation"])[3])["filesystem"]["network"]
    assert not service.dispatch(dict(request, method="lookup"), [1])["active"]
    with pytest.raises(ValueError, match="cleanup-only"):
        service.dispatch(request, [1, 2, 3])
    with pytest.raises(ValueError, match="runtime-stopped"):
        service.dispatch(dict(request, method="retire"), [1])
    with patch("agentsuite_guardd.neutral_service.task_ids", return_value=[]):
        assert service.dispatch(dict(request, method="retire"), [1])["retired"]
    assert not Path(service.row(request["operation"])[4]).exists()
    assert service.row(request["operation"])[2] == "RETIRED"


def test_no_filesystem_only_fallback_for_complete_requirement(context):
    service, request, _ = combined_context(context)
    service.container = None
    with pytest.raises(ValueError, match="not configured"):
        service.dispatch(request, [1, 2, 3])
    assert service.row(request["operation"]) is None
    assert not service.filesystem.installs




def readback(native):
    ids = {name: number + 1 for number, name in enumerate(native.MAPS)}
    programs = {}
    for number, name in enumerate(native.PROGRAMS):
        if name in FilesystemNative.PROGRAMS:
            dependencies = set(FilesystemNative.MAPS)
        elif name in {"network_connect4", "network_sendmsg4", "network_egress"}:
            dependencies = {"container_endpoints"}
        elif name in {"network_socket_sendmsg", "network_socket_connect"}:
            dependencies = {"container_endpoints", "guarded_targets"}
        else:
            dependencies = {"guarded_targets"}
        programs[name] = dict(id=number + 100, map_ids=[ids[key] for key in dependencies])
    return dict(maps={name: dict(id=value) for name, value in ids.items()},
                programs=programs, links={})


def test_combined_dependency_readback_accepts_only_exact_program_maps():
    native = ContainerNative.__new__(ContainerNative)
    proof = readback(native)
    with patch.object(Native, "verify", return_value=proof):
        assert native.verify("unused", 99, {})["filesystem"] == {}
        for name, program in proof["programs"].items():
            original = program["map_ids"].copy()
            program["map_ids"].append(999)
            with pytest.raises(ValueError, match="dependency"):
                native.verify("unused", 99, {})
            program["map_ids"] = original[1:]
            with pytest.raises(ValueError, match="dependency"):
                native.verify("unused", 99, {})
            program["map_ids"] = original


def test_combined_endpoint_map_keeps_transport_and_wildcard_distinct():
    native = ContainerNative.__new__(ContainerNative)
    spec = dict(generation=7, entries=[], network=[
        ["10.0.0.2", 53, 6], ["10.0.0.2", 53, 17], ["10.0.0.2", 0, 6],
    ])
    with patch("agentsuite_guardd.native_filesystem.validate_cgroup_fd",
               return_value=SimpleNamespace(cgroup_id=123)):
        entries = native.entries(99, spec)
    assert len(entries["container_endpoints"]) == 3
    assert len(entries["guarded_targets"]) == 1
