"""Wire interoperability; no native enforcement claims."""
import pytest

from agentsuite_guardd.enforcement_protocol import (
    requirement_digest, target_facts_digest, validate_request,
)
from orka_enforcement.v1 import enforcement_pb2 as wire


def request():
    return wire.EnsureRequest(
        binding_id="container-1",
        requirement=wire.Requirement(
            format="example.policy/v1", policy=b" complete policy \n",
            required_capabilities=["filesystem/deny-write/v1", "network/egress-allow/v1"],
            mode=wire.Requirement.MODE_ENFORCE,
        ),
        target_facts=wire.TargetFacts(
            format="example.container/v1", value=b'{"container":"incarnation-1"}',
        ),
    )


def test_go_python_identities_preserve_exact_policy_bytes():
    value = request()
    before = value.requirement.policy
    validate_request(value)
    assert value.requirement.policy == before
    assert requirement_digest(value.requirement) == (
        "sha256:4579b629d512e51992545c0782c96074c7914c767842b059cf9df678bc13ed30"
    )
    assert target_facts_digest(value.target_facts) == (
        "sha256:e6e7e0369ff73d0aebb869ee4c30d981ff11fdf35c4c58fdd033ce5da052c31a"
    )
    value.requirement.policy = b"complete policy"
    assert requirement_digest(value.requirement) != requirement_digest(request().requirement)


@pytest.mark.parametrize("field", ["binding_id", "requirement", "target_facts"])
def test_missing_authority_is_rejected(field):
    value = request()
    value.ClearField(field)
    with pytest.raises(ValueError):
        validate_request(value)


@pytest.mark.parametrize("mode", [wire.Requirement.MODE_UNSPECIFIED, 99])
def test_non_enforcing_modes_are_rejected(mode):
    value = request()
    value.requirement.mode = mode
    with pytest.raises(ValueError):
        validate_request(value)
