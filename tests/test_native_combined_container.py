"""Opt-in real CRI/container/syscall proof, independent of model inference."""
from contextlib import ExitStack, contextmanager
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import uuid

import pytest

from agentsuite_guardd.container_policy import FORMAT
from agentsuite_guardd.kubernetes_provider import KubernetesEnforcementProvider
from agentsuite_guardd.kubernetes_target import KubernetesTargetResolver, TargetPending
from agentsuite_guardd.model import canonical
from agentsuite_guardd.native_container import ContainerNative
from agentsuite_guardd.neutral_service import Service
from orka_enforcement.v1 import enforcement_pb2 as wire
from test_native_kubernetes_provider import owned_kubernetes_container


@contextmanager
def echo_server(address, udp=False):
    received = []

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            if udp:
                data, stream = self.request
                received.append(data)
                stream.sendto(data, self.client_address)
            else:
                self.request.settimeout(3)
                data = self.request.recv(128)
                received.append(data)
                self.request.sendall(data)

    server = (socketserver.UDPServer if udp else socketserver.ThreadingTCPServer)(
        (address, 0), Echo,
    )
    thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=0.05))
    thread.start()
    try:
        yield server.server_address[1], received
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def udp_baseline(resolved, address, port):
    script = """
import json, socket, sys
address, port = sys.argv[1], int(sys.argv[2])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(2)
    client.sendto(b"baseline-unconnected", (address, port))
    data, peer = client.recvfrom(128)
    assert data == b"baseline-unconnected"
    result = {"replyAddress": peer[0], "connectedEcho": False}
    client.connect((address, port))
    client.send(b"baseline-connected")
    try:
        result["connectedEcho"] = client.recv(128) == b"baseline-connected"
    except TimeoutError as error:
        result["connectedFailure"] = type(error).__name__
print(json.dumps(result))
"""
    return json.loads(subprocess.check_output([
        "nsenter", "--net=/proc/self/fd/" + str(resolved.fds[2]), "--",
        sys.executable, "-c", script, address, str(port),
    ], pass_fds=[resolved.fds[2]], timeout=10))


PROBE = Path(__file__).parent / "native/container_probe.py"


@contextmanager
def prepared_sockets(resolved, operation, count, **extra):
    receiver, transfer = socket.socketpair()
    with receiver, transfer, ExitStack() as stack:
        config = dict(cgroup=resolved.fds[0], netns=resolved.fds[2],
                      transfer=transfer.fileno(), **extra)
        subprocess.run(
            [sys.executable, str(PROBE), operation, json.dumps(config)],
            pass_fds=(resolved.fds[0], resolved.fds[2], transfer.fileno()),
            capture_output=True, check=True, timeout=10,
        )
        receiver.settimeout(2)
        payload, ancillary, flags, _ = receiver.recvmsg(128, socket.CMSG_SPACE(4 * count))
        assert payload == b"prepared" and flags == 0 and len(ancillary) == 1
        level, kind, raw = ancillary[0]
        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        descriptors = array.array("i")
        descriptors.frombytes(raw)
        assert len(descriptors) == count
        yield [stack.enter_context(socket.socket(fileno=fd)) for fd in descriptors]


@contextmanager
def prepared_unix_client(resolved):
    with tempfile.TemporaryDirectory(prefix="gd-unix-") as directory, \
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        path = directory + "/peer"
        listener.bind(path)
        listener.listen(1)
        with prepared_sockets(resolved, "prepare-unix", 1, listener=path) as clients:
            peer, _ = listener.accept()
            with peer:
                yield clients[0]


def mapped_config(sockets, client):
    return dict(listener=sockets[0].fileno(), blocked=sockets[2].fileno(),
                ipv6=sockets[4].fileno(), allowedPort=client.getsockname()[1])


def probe(resolved, address, allowed_tcp, denied_tcp, allowed_udp, denied_udp,
          receipt, prepared, pairs, mapped, mapped_client):
    with socket.create_connection((address, denied_tcp), timeout=2) as inherited, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unconnected, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as allowed, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as inherited_udp, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as allowed_inherited_udp, \
            tempfile.TemporaryFile() as source:
        foreign_unix, foreign_peer = socket.socketpair()
        with foreign_unix, foreign_peer:
            unconnected.settimeout(2)
            allowed.settimeout(2)
            source.write(b"forbidden")
            source.flush()
            config = dict(
                cgroup=resolved.fds[0], netns=resolved.fds[2], pid=resolved.target["pid"],
                address=address, allowedTCP=allowed_tcp, deniedTCP=denied_tcp,
                allowedUDP=allowed_udp, deniedUDP=denied_udp,
                connectedTCP=inherited.fileno(), unconnectedTCP=unconnected.fileno(),
                unconnectedAllowedTCP=allowed.fileno(), foreignUnix=foreign_unix.fileno(),
                targetOwnedUnix=prepared.fileno(), source=source.fileno(),
                unconnectedUDP=inherited_udp.fileno(),
                unconnectedAllowedUDP=allowed_inherited_udp.fileno(),
                preactivatedUnix={
                    name: [pairs[index * 2].fileno(), pairs[index * 2 + 1].fileno()]
                    for index, name in enumerate(("stream", "datagram", "seqpacket"))
                },
                mapped=mapped_config(mapped, mapped_client),
            )
            result = subprocess.run(
                [sys.executable, str(PROBE), "probe", json.dumps(config)],
                pass_fds=(resolved.fds[0], resolved.fds[2], inherited.fileno(),
                          unconnected.fileno(), allowed.fileno(), foreign_unix.fileno(),
                          prepared.fileno(), source.fileno(), inherited_udp.fileno(),
                          allowed_inherited_udp.fileno(), *(pair.fileno() for pair in pairs),
                          *(stream.fileno() for stream in mapped)),
                capture_output=True, timeout=30,
            )
            receipt.write_bytes(result.stdout)
            decoded = json.loads(result.stdout)
            assert result.returncode == 0 and decoded["ok"], decoded
            return decoded


def probe_mapped_descendant(resolved, mapped, client, receipt):
    os.mkdir("mapped-probe", dir_fd=resolved.fds[0])
    try:
        child = os.open("mapped-probe", os.O_RDONLY | os.O_DIRECTORY, dir_fd=resolved.fds[0])
        try:
            config = dict(cgroup=child, netns=resolved.fds[2], mapped=mapped_config(mapped, client))
            result = subprocess.run(
                [sys.executable, str(PROBE), "probe-mapped", json.dumps(config)],
                pass_fds=(child, resolved.fds[2], *(stream.fileno() for stream in mapped)),
                capture_output=True, timeout=10,
            )
            receipt.write_bytes(result.stdout)
            decoded = json.loads(result.stdout)
            assert result.returncode == 0 and decoded["ok"], decoded
            return decoded
        finally:
            os.close(child)
    finally:
        os.rmdir("mapped-probe", dir_fd=resolved.fds[0])


def test_combined_real_container_syscalls_and_recovered_retirement(tmp_path, owned_kubernetes_container):
    object_path = os.environ.get("GUARDD_CONTAINER_OBJECT")
    if not object_path:
        pytest.skip("explicit combined native object required")
    kubectl, facts = owned_kubernetes_container
    import shutil
    resolver = KubernetesTargetResolver(
        facts["nodeName"], facts["nodeUID"], [shutil.which("crictl") or "/usr/local/bin/crictl"],
    )
    node = json.loads(kubectl("get", "node", facts["nodeName"], "-o", "json").stdout)
    addresses = [value["address"] for value in node["status"]["addresses"]
                 if value["type"] == "InternalIP" and ":" not in value["address"]]
    assert len(addresses) == 1
    address = addresses[0]
    pins = Path("/sys/fs/bpf") / ("guardd-combined-" + uuid.uuid4().hex)
    database = tmp_path / "combined.db"
    backend = ContainerNative(object_path)
    service = Service(database, pins, None, container=backend)
    provider = KubernetesEnforcementProvider(service, resolver, ["spiffe://orka.ai/controller"])
    binding = "combined:" + hashlib.sha256(canonical(facts)).hexdigest()
    retirement = wire.RetireRequest(binding_id=binding)
    try:
        with ExitStack() as stack:
            allowed_tcp, _ = stack.enter_context(echo_server(address))
            denied_tcp, blocked_tcp_data = stack.enter_context(echo_server(address))
            allowed_udp, _ = stack.enter_context(echo_server(address, udp=True))
            denied_udp, blocked_udp_data = stack.enter_context(echo_server(address, udp=True))
            with resolver.resolve(wire.TargetFacts(
                    format="orka.kubernetes-container/v1", value=canonical(facts))) as resolved:
                prepared = stack.enter_context(prepared_unix_client(resolved))
                pairs = stack.enter_context(prepared_sockets(resolved, "prepare-unix-pairs", 6))
                mapped = stack.enter_context(prepared_sockets(resolved, "prepare-mapped", 5))
                mapped_clients = stack.enter_context(
                    prepared_sockets(resolved, "prepare-mapped-clients", 2),
                )
                for client in mapped_clients:
                    client.settimeout(2)
                assert mapped[1].getsockname()[1] not in {
                    client.getsockname()[1] for client in mapped_clients
                }
                with echo_server("0.0.0.0", udp=True) as (wildcard_port, _):
                    wildcard_baseline = udp_baseline(resolved, address, wildcard_port)
                baseline = udp_baseline(resolved, address, allowed_udp)
                (tmp_path / "udp-baseline.json").write_bytes(canonical(dict(
                    wildcard=wildcard_baseline, explicitAddress=baseline,
                )))
                assert baseline == dict(replyAddress=address, connectedEcho=True)
            capabilities = ["filesystem/deny-write/v1", "network/egress-allow/v1"]
            policy = canonical(dict(
                version=FORMAT, denyWritePaths=["/protected"], requiredCapabilities=capabilities,
                network=dict(egressAllow=[
                    dict(address=address, port=allowed_tcp, protocol="TCP"),
                    dict(address=address, port=allowed_udp, protocol="UDP"),
                ] + [dict(address="127.0.0.1", port=client.getsockname()[1], protocol="TCP")
                     for client in mapped_clients]),
            ))
            request = wire.EnsureRequest(
                binding_id=binding,
                requirement=wire.Requirement(
                    format=FORMAT, policy=policy, required_capabilities=capabilities,
                    mode=wire.Requirement.MODE_ENFORCE,
                ),
                target_facts=wire.TargetFacts(format="orka.kubernetes-container/v1", value=canonical(facts)),
            )
            admission = provider.ensure(request)
            assert admission.HasField("enforced")
            with resolver.resolve(request.target_facts) as resolved:
                mapped_clients[0].connect(("127.0.0.1", mapped[0].getsockname()[1]))
                result = probe(resolved, address, allowed_tcp, denied_tcp, allowed_udp, denied_udp,
                               tmp_path / "probe-result.json", prepared, pairs, mapped, mapped_clients[0])
                assert mapped_clients[0].recv(128) == b"allowed-mapped-response"
                mapped_clients[1].connect(("127.0.0.1", mapped[0].getsockname()[1]))
                descendant = probe_mapped_descendant(
                    resolved, mapped, mapped_clients[1], tmp_path / "descendant-probe-result.json",
                )
                assert mapped_clients[1].recv(128) == b"allowed-mapped-response"
            assert not any(blocked_tcp_data)
            assert not blocked_udp_data
            with pytest.raises(TargetPending, match="stop the physical container"):
                provider.retire(retirement)
            provider.close()
            service.close()
            service = Service(database, pins, None, container=backend)
            provider = KubernetesEnforcementProvider(service, resolver, ["spiffe://orka.ai/controller"])
            recovered = provider.ensure(request)
            assert recovered.enforced.evidence == admission.enforced.evidence
            (tmp_path / "combined-kernel-evidence.json").write_bytes(canonical(dict(
                policy=json.loads(policy), target=facts, checks=result, descendantChecks=descendant,
                readback=json.loads(admission.enforced.evidence),
                recoveredReadback=json.loads(recovered.enforced.evidence),
            )))
    finally:
        kubectl("-n", facts["namespace"], "delete", "pod", "worker",
                "--ignore-not-found", "--wait=true", "--timeout=60s")
        try:
            assert provider.retire(retirement).HasField("retired")
            assert not any(pins.iterdir())
            pins.rmdir()
        finally:
            provider.close()
            service.close()
