import base64


import copy


import json


from pathlib import Path


from types import SimpleNamespace


from unittest.mock import patch


import pytest


from agentsuite_guardd.container_policy import FORMAT, ContainerPlan, compile_container


from agentsuite_guardd.model import canonical, policy_digest


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
    plan = compile_policy(value)
    assert isinstance(plan, ContainerPlan)
    assert plan.endpoints == (("10.0.0.2", 443, 6), ("10.0.0.53", 53, 17),
                              ("10.0.0.3", 0, 6))
    assert plan.deny_write_paths == ("/protected",)
    assert value == original
    value["requiredCapabilities"].reverse()
    assert compile_policy(value).endpoints == plan.endpoints
    raw = canonical(value)
    with pytest.raises(ValueError, match="ordered capabilities"):
        compile_container(raw, policy_digest(raw), CAPABILITIES)
    value["network"]["egressAllow"] = []
    assert compile_policy(value).endpoints == ()


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
        compile_policy(value)


def test_no_normalization_or_digest_substitution():
    raw = canonical(policy())
    for changed in (raw + b"\n", raw.replace(b'"version":', b'"version":"extra","version":')):
        with pytest.raises(ValueError):
            compile_container(changed, policy_digest(changed), CAPABILITIES)
    with pytest.raises(ValueError, match="digest"):
        compile_container(raw, "sha256:" + "0" * 64, CAPABILITIES)



def compile_policy(value):
    raw = canonical(value)
    return compile_container(raw, policy_digest(raw), value['requiredCapabilities'])
