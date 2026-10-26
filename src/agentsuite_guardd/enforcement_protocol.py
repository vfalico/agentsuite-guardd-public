"""Provider-neutral message validation; policy bytes remain opaque and unchanged."""
from hashlib import sha256

from orka_enforcement.v1 import enforcement_pb2 as wire

MAX_POLICY_BYTES = 512 << 10
MAX_FACTS_BYTES = 64 << 10
MAX_RPC_BYTES = 2 << 20


def digest(domain, message):
    value = message.SerializeToString(deterministic=True)
    return "sha256:" + sha256(domain.encode("ascii") + b"\0" + value).hexdigest()


def requirement_digest(requirement):
    return digest("orka.enforcement.requirement/v1", requirement)


def target_facts_digest(facts):
    return digest("orka.enforcement.target-facts/v1", facts)


def text(value, maximum):
    return bool(value) and len(value.encode("utf-8")) <= maximum and value.strip() == value and "\0" not in value


def validate_request(request):
    if not text(request.binding_id, 128):
        raise ValueError("enforcement requires a bounded immutable binding ID")
    requirement = request.requirement
    if (not request.HasField("requirement") or not text(requirement.format, 256)
            or requirement.mode != wire.Requirement.MODE_ENFORCE
            or not 0 < len(requirement.policy) <= MAX_POLICY_BYTES
            or not 0 < len(requirement.required_capabilities) <= 32):
        raise ValueError("enforcement requires a complete bounded enforce-mode requirement")
    capabilities = requirement.required_capabilities
    if (len(set(capabilities)) != len(capabilities)
            or not all(text(capability, 256) for capability in capabilities)):
        raise ValueError("enforcement capabilities must be bounded, nonempty and unique")
    facts = request.target_facts
    if (not request.HasField("target_facts") or not text(facts.format, 256)
            or not 0 < len(facts.value) <= MAX_FACTS_BYTES):
        raise ValueError("enforcement requires bounded versioned target facts")
