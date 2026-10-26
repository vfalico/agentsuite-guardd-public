"""Trusted exec child for opt-in native tests; no threaded-parent Python fork."""
import array
from contextlib import ExitStack
import ctypes
import encodings.idna
import errno
import json
import os
import socket
import sys


def enter(config):
    cgroup = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC, dir_fd=config["cgroup"])
    try:
        os.write(cgroup, str(os.getpid()).encode())
    finally:
        os.close(cgroup)
    enter_network(config)


def enter_network(config):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(config["netns"], 0) != 0:
        raise OSError(ctypes.get_errno(), "setns")


def send_prepared(config, descriptors):
    with socket.socket(fileno=config["transfer"]) as transfer:
        transfer.sendmsg([b"prepared"], [
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors)),
        ])


def mapped_responses(config, results):
    with ExitStack() as stack:
        listener, blocked, ipv6 = [
            stack.enter_context(socket.socket(fileno=config["mapped"][name]))
            for name in ("listener", "blocked", "ipv6")
        ]
        listener.settimeout(2)
        accepted, peer = listener.accept()
        with accepted:
            assert accepted.family == socket.AF_INET6
            assert socket.inet_pton(socket.AF_INET6, peer[0]) == (
                b"\x00" * 10 + b"\xff\xff\x7f\x00\x00\x01"
            )
            assert peer[1] == config["mapped"]["allowedPort"]
            accepted.sendall(b"allowed-mapped-response")
        results["mapped_ipv4_accept_and_response"] = True
        results["mapped_allowed_peer_port"] = peer[1]
        for name, stream in (("mapped_denied_response_port", blocked),
                             ("actual_ipv6_response", ipv6)):
            try:
                stream.send(b"forbidden")
            except OSError as error:
                assert error.errno == errno.EACCES, (name, error.errno)
                results[name] = error.errno
            else:
                raise AssertionError(name + " unexpectedly allowed")


def run(config, results):
    enter(config)
    os.chroot("/proc/" + str(config["pid"]) + "/root")
    os.chdir("/")
    address = config["address"]
    failures = []

    def denied(name, operation):
        try:
            operation()
        except OSError as error:
            if error.errno not in {errno.EACCES, errno.EPERM}:
                raise
            results[name] = error.errno
        else:
            results[name] = "UNEXPECTEDLY_ALLOWED"
            failures.append(name)

    def write_file(path, data):
        with open(path, "w") as stream:
            stream.write(data)

    denied("filesystem_create", lambda: write_file("/protected/forbidden", "bad"))
    denied("filesystem_overwrite", lambda: write_file("/protected/canary", "bad"))
    write_file("/tmp/combined-allowed", "allowed")
    with open("/tmp/combined-allowed") as stream:
        assert stream.read() == "allowed"
    with open("/protected/canary") as stream:
        assert stream.read() == "original"
    results["filesystem_allowed_read_write"] = True
    with socket.create_connection((address, config["allowedTCP"]), timeout=2) as client:
        client.sendall(b"allowed-tcp")
        assert client.recv(128) == b"allowed-tcp"
    results["tcp_allowed"] = True
    mapped_responses(config, results)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        denied("tcp_connect", lambda: client.connect((address, config["deniedTCP"])))
    inherited = socket.socket(fileno=config["connectedTCP"])
    unconnected = socket.socket(fileno=config["unconnectedTCP"])
    allowed = socket.socket(fileno=config["unconnectedAllowedTCP"])
    foreign_unix = socket.socket(fileno=config["foreignUnix"])
    target_owned_unix = socket.socket(fileno=config["targetOwnedUnix"])
    inherited_udp = socket.socket(fileno=config["unconnectedUDP"])
    allowed_inherited_udp = socket.socket(fileno=config["unconnectedAllowedUDP"])
    for client in (inherited, unconnected, allowed):
        client.settimeout(2)
    denied("inherited_tcp_connect", lambda: unconnected.connect((address, config["deniedTCP"])))
    allowed.connect((address, config["allowedTCP"]))
    allowed.sendall(b"allowed-inherited-tcp")
    assert allowed.recv(128) == b"allowed-inherited-tcp"
    results["inherited_allowed_tcp"] = True
    denied("inherited_tcp_send", lambda: inherited.send(b"bad"))
    denied("inherited_tcp_write", lambda: os.write(inherited.fileno(), b"bad"))
    denied("inherited_tcp_writev", lambda: os.writev(inherited.fileno(), [b"bad"]))
    denied("inherited_tcp_sendmsg", lambda: inherited.sendmsg([b"bad"]))
    denied("inherited_tcp_sendfile",
           lambda: os.sendfile(inherited.fileno(), config["source"], 0, 9))
    denied("foreign_unix", lambda: foreign_unix.send(b"bad"))
    denied("target_owned_unix_foreign_peer", lambda: target_owned_unix.send(b"bad"))
    for name, descriptors in config["preactivatedUnix"].items():
        with socket.socket(fileno=descriptors[0]) as client, \
                socket.socket(fileno=descriptors[1]) as peer:
            if name == "stream":
                client.send(b"allowed-preactivated-stream")
                assert peer.recv(128) == b"allowed-preactivated-stream"
                results["preactivated_unix_stream"] = True
            else:
                denied("preactivated_unix_" + name, lambda: client.send(b"bad"))
    denied("inherited_udp_connect",
           lambda: inherited_udp.connect((address, config["deniedUDP"])))
    allowed_inherited_udp.settimeout(2)
    allowed_inherited_udp.connect((address, config["allowedUDP"]))
    allowed_inherited_udp.send(b"allowed-inherited-udp")
    assert allowed_inherited_udp.recv(128) == b"allowed-inherited-udp"
    results["inherited_allowed_udp"] = True
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(b"allowed-udp", (address, config["allowedUDP"]))
        assert client.recvfrom(128)[0] == b"allowed-udp"
        denied("udp_sendto", lambda: client.sendto(b"bad", (address, config["deniedUDP"])))
        client.connect((address, config["allowedUDP"]))
        client.send(b"allowed-connected-udp")
        assert client.recv(128) == b"allowed-connected-udp"
        denied("udp_override", lambda: client.sendto(b"bad", (address, config["deniedUDP"])))
    results["udp_allowed_connected_and_unconnected"] = True
    local, peer = socket.socketpair()
    try:
        local.send(b"local")
        assert peer.recv(5) == b"local"
    finally:
        local.close()
        peer.close()
    results["internal_unix_pair"] = True
    denied("ipv6", lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
    denied("raw_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP))
    if failures:
        raise AssertionError("unexpectedly allowed: " + ", ".join(failures))


if __name__ == "__main__":
    config = json.loads(sys.argv[2])
    if sys.argv[1] == "prepare-unix":
        enter(config)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(config["listener"])
            send_prepared(config, [client.fileno()])
    elif sys.argv[1] == "prepare-unix-pairs":
        enter(config)
        with ExitStack() as stack:
            descriptors = []
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
                client, peer = socket.socketpair(type=kind)
                stack.enter_context(client)
                stack.enter_context(peer)
                descriptors.extend((client.fileno(), peer.fileno()))
            send_prepared(config, descriptors)
    elif sys.argv[1] == "prepare-mapped":
        enter(config)
        with ExitStack() as stack:
            listener = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            listener.settimeout(2)
            listener.bind(("::", 0))
            listener.listen(4)
            descriptors = [listener.fileno()]
            for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                client = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
                client.settimeout(2)
                client.connect((address, listener.getsockname()[1]))
                accepted, _ = listener.accept()
                stack.enter_context(accepted)
                accepted.sendall(b"preactivation-baseline")
                assert client.recv(128) == b"preactivation-baseline"
                descriptors.extend((client.fileno(), accepted.fileno()))
            send_prepared(config, descriptors)
    elif sys.argv[1] == "prepare-mapped-clients":
        enter_network(config)
        with ExitStack() as stack:
            clients = [
                stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                for _ in range(2)
            ]
            for client in clients:
                client.settimeout(2)
                client.bind(("127.0.0.1", 0))
            send_prepared(config, [client.fileno() for client in clients])
    else:
        results = {}
        try:
            if sys.argv[1] == "probe-mapped":
                enter(config)
                mapped_responses(config, results)
            else:
                run(config, results)
            result = dict(ok=True, checks=results)
        except Exception as error:  # AUDITED: BROAD — retain exact failed probe and nonzero status
            result = dict(ok=False, error=type(error).__name__ + ": " + str(error), checks=results)
        print(json.dumps(result, sort_keys=True))
        sys.exit(0 if result["ok"] else 1)
