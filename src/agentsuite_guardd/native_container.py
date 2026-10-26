"""One immutable kernel object and complete inventory for combined enforcement."""
import ipaddress
import struct

from .native_filesystem import FilesystemNative
from .native_network import Native


class ContainerNative(FilesystemNative):
    HOOKS = dict(FilesystemNative.HOOKS, **{
        "network_" + hook: hook for hook in (
            "socket_create", "file_receive", "socket_accept", "socket_bind",
            "socket_connect", "socket_sendmsg",
        )
    })
    PROGRAMS = dict(
        {name: ("lsm", None) for name in HOOKS},
        network_connect4=("cgroup", 10), network_sendmsg4=("cgroup", 14),
        network_egress=("cgroup", 1),
    )
    MAPS = dict(FilesystemNative.MAPS, container_endpoints=("hash", 12, 4, 4096))

    def entries(self, cgroup, spec):
        return dict(super().entries(cgroup, spec), container_endpoints={
            ipaddress.IPv4Address(address).packed + struct.pack("=II", port, protocol):
                struct.pack("=I", 1)
            for address, port, protocol in spec["network"]
        })

    def verify(self, directory, cgroup, spec):
        proof = Native.verify(self, directory, cgroup, spec)
        ids = {name: value["id"] for name, value in proof["maps"].items()}
        for name, program in proof["programs"].items():
            if name in FilesystemNative.PROGRAMS:
                dependencies = set(FilesystemNative.MAPS)
            elif name in {"network_connect4", "network_sendmsg4", "network_egress"}:
                dependencies = {"container_endpoints"}
            elif name in {"network_socket_sendmsg", "network_socket_connect"}:
                dependencies = {"guarded_targets", "container_endpoints"}
            else:
                dependencies = {"guarded_targets"}
            if set(program.get("map_ids", [])) != {ids[item] for item in dependencies}:
                raise ValueError("combined program policy-map dependency mismatch: " + name)
        if len({p["id"] for p in proof["programs"].values()}) != len(self.PROGRAMS):
            raise ValueError("duplicate combined programs")
        return dict(proof, filesystem=spec)
