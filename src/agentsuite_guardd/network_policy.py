"""Exact ordinary Suite network-v2 compilation. No runtime envelope semantics."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import struct

FORMAT = "agentsuite.policy/v2"
CAPABILITY = "network/egress-allow/v1"


def exact_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate policy key")
        value[key] = item
    return value


@dataclass(frozen=True)
class NetworkPlan:
    policy_bytes: bytes
    digest: str
    endpoints: tuple[tuple[str, int], ...]


def compile_network(raw: bytes, digest: str, capabilities: list[str]) -> NetworkPlan:
    if type(raw) is not bytes or not 0 < len(raw) <= 262144:
        raise ValueError("policy bytes must be 1..262144")
    if capabilities != [CAPABILITY]:
        raise ValueError("unsupported complete capability set")
    framed = b"agentsuite-effective-policy\0v1\0" + struct.pack(">Q", len(raw)) + raw
    if digest != "sha256:" + hashlib.sha256(framed).hexdigest():
        raise ValueError("Suite payload digest mismatch")
    policy = json.loads(raw, object_pairs_hook=exact_object)
    if type(policy) is not dict or set(policy) != {"version", "network", "requiredCapabilities"}:
        raise ValueError("unsupported complete effective policy")
    if policy["version"] != FORMAT or policy["requiredCapabilities"] != [CAPABILITY]:
        raise ValueError("unsupported policy format or capability set")
    network = policy["network"]
    if type(network) is not dict or set(network) != {"egressAllow"}:
        raise ValueError("unsupported network fields")
    rules = network["egressAllow"]
    if type(rules) is not list or len(rules) > 4096:
        raise ValueError("endpoint capacity exceeded")
    endpoints = []
    seen = set()
    for rule in rules:
        if type(rule) is not dict or set(rule) != {"address", "port", "protocol"}:
            raise ValueError("unsupported endpoint fields")
        if type(rule["address"]) is not str:
            raise ValueError("address must be literal IPv4")
        ip = ipaddress.IPv4Address(rule["address"])
        if str(ip) != rule["address"] or ip.is_multicast or ip.is_unspecified:
            raise ValueError("unsupported address")
        if rule["protocol"] != "TCP" or type(rule["port"]) is not int or not 1 <= rule["port"] <= 65535:
            raise ValueError("unsupported transport or port")
        endpoint = (rule["address"], rule["port"])
        if endpoint in seen:
            raise ValueError("duplicate effective endpoint")
        seen.add(endpoint)
        endpoints.append(endpoint)
    if json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() != raw:
        raise ValueError("noncanonical effective policy")
    return NetworkPlan(raw, digest, tuple(endpoints))
