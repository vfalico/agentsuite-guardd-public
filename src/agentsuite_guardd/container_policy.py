"""Complete filesystem and IPv4 TCP/UDP policy; no implicit runtime grants."""
from dataclasses import dataclass
import ipaddress
import json
import posixpath

from .model import canonical, policy_digest
from .network_policy import exact_object
from .policy import BackendPlan, OPERATIONS, _utf16_sort_key

FORMAT = "agentsuite.policy/v3"
CAPABILITIES = frozenset({"filesystem/deny-write/v1", "network/egress-allow/v1"})


@dataclass(frozen=True)
class ContainerPlan(BackendPlan):
    endpoints: tuple[tuple[str, int, int], ...]


def compile_container(raw, digest, capabilities):
    if type(raw) is not bytes or not 0 < len(raw) <= 262144:
        raise ValueError("complete policy bytes must be 1..262144")
    if policy_digest(raw) != digest:
        raise ValueError("complete policy digest mismatch")
    if (type(capabilities) is not list or len(capabilities) != 2
            or any(type(item) is not str for item in capabilities)
            or frozenset(capabilities) != CAPABILITIES):
        raise ValueError("complete filesystem and network capabilities required")
    policy = json.loads(raw, object_pairs_hook=exact_object)
    if (type(policy) is not dict
            or set(policy) != {"version", "denyWritePaths", "network", "requiredCapabilities"}
            or policy["version"] != FORMAT
            or policy["requiredCapabilities"] != capabilities):
        raise ValueError("complete policy fields, version and ordered capabilities must match")
    paths = policy["denyWritePaths"]
    if (type(paths) is not list or not paths
            or any(type(path) is not str for path in paths)):
        raise ValueError("denyWritePaths must be a nonempty list of absolute paths")
    if len(paths) != len(set(paths)) or paths != sorted(paths, key=_utf16_sort_key):
        raise ValueError("policy paths must be unique and canonically ordered")
    for path in paths:
        if (not path.startswith("/") or path == "/" or posixpath.normpath(path) != path
                or "\0" in path):
            raise ValueError("invalid deny path")
    network = policy["network"]
    if type(network) is not dict or set(network) != {"egressAllow"}:
        raise ValueError("network requires only explicit egressAllow")
    rules = network["egressAllow"]
    if type(rules) is not list or len(rules) > 4096:
        raise ValueError("egressAllow exceeds endpoint capacity")
    endpoints, seen = [], set()
    for rule in rules:
        if type(rule) is not dict or set(rule) != {"address", "port", "protocol"}:
            raise ValueError("endpoint requires address, port and protocol")
        address, port, protocol = rule["address"], rule["port"], rule["protocol"]
        if type(address) is not str:
            raise ValueError("endpoint must use a literal IPv4 address")
        ip = ipaddress.IPv4Address(address)
        if str(ip) != address or ip.is_multicast or ip.is_unspecified or int(ip) == 0xffffffff:
            raise ValueError("unsupported endpoint address")
        if not (port == "*" and type(port) is str
                or type(port) is int and 1 <= port <= 65535):
            raise ValueError("endpoint port must be 1..65535 or explicit '*'")
        if type(protocol) is not str or protocol not in {"TCP", "UDP"}:
            raise ValueError("endpoint protocol must be TCP or UDP")
        endpoint = (address, 0 if port == "*" else port, 6 if protocol == "TCP" else 17)
        if endpoint in seen:
            raise ValueError("duplicate endpoint")
        endpoints.append(endpoint)
        seen.add(endpoint)
    if canonical(policy) != raw:
        raise ValueError("complete policy bytes must be canonical")
    return ContainerPlan(digest, tuple(paths), OPERATIONS, "held-native", tuple(endpoints))
