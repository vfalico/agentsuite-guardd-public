"""Runtime-neutral exact cgroup enforcement over authenticated local seqpackets.

Only the runtime owns process preparation, release and stop. This service never
executes a workload, consumes runtime journals, or selects an execution target.
"""
from __future__ import annotations
import array
import base64
import hashlib
import fcntl
import errno
import logging
import stat
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import struct
import subprocess
import threading
import time

from .network_policy import compile_network
from .target import validate_cgroup_fd, task_ids, read_events
from .native_network import Native
from .namespace_policy import NamespacePolicy

VERSION = "execution-enforcement/v1"
MAX_FRAME = 1048576


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identity(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("complete exact fields required: " + ",".join(sorted(keys)))


def requirement(value):
    exact(value, {"format", "bytes", "digest", "capabilities"})
    if value["format"] != "agentsuite.policy/v2":
        raise ValueError("unsupported complete policy format")
    raw = base64.b64decode(value["bytes"], validate=True)
    return compile_network(raw, value["digest"], value["capabilities"])


def target_identity(fd):
    return dict(boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip(), cgroup=validate_cgroup_fd(fd).dict())


def pidfd_identity(fd):
    """Kernel pidfd metadata in this procfs view, including nested PID aliases.

    NSpid is kernel generated. A different numeric PID never changes the
    authenticated cgroup/start/netns scope. Dead handles and ordinary FDs fail.
    """
    fields = {}
    for line in Path("/proc/self/fdinfo/" + str(fd)).read_text().splitlines():
        key, sep, value = line.partition(":")
        if sep and key in {"Pid", "NSpid"}:
            if key in fields:
                raise ValueError("duplicate pidfd metadata")
            fields[key] = value.strip()
    try:
        pid = int(fields["Pid"])
        namespace_ids = [int(n) for n in fields["NSpid"].split()]
    except (KeyError, ValueError) as error:
        raise ValueError("live pidfd metadata required") from error
    if pid <= 1 or not namespace_ids or namespace_ids[0] != pid or any(n <= 0 for n in namespace_ids):
        raise ValueError("live pidfd namespace identity required")
    return pid, namespace_ids


def held_target(fds, target):
    exact(target, {"boot", "cgroup", "pid", "start", "netns", "generation"})
    if type(target["generation"]) is not int or target["generation"] < 1:
        raise ValueError("positive incarnation generation required")
    if target_identity(fds[0]) != {k: target[k] for k in ["boot", "cgroup"]}:
        raise ValueError("target cgroup/boot changed")
    # The request PID is observational metadata in the runtime's PID
    # namespace, not receiver-local authority. Resolve only from the live
    # transferred pidfd; never /proc/<caller-number> or a friendly name.
    observed = target["pid"]
    if type(observed) is not int or observed <= 1:
        raise ValueError("invalid held process")
    pid, namespace_ids = pidfd_identity(fds[1])
    if observed not in namespace_ids:
        raise ValueError("pidfd namespace identity mismatch")
    start = Path("/proc/" + str(pid) + "/stat").read_text().rsplit(")", 1)[1].split()[19]
    if target["start"] != start or task_ids(fds[0]) != [pid]:
        raise ValueError("held target membership/start mismatch")
    ns = os.fstat(fds[2])
    actual = os.stat("/proc/" + str(pid) + "/ns/net")
    if (ns.st_dev, ns.st_ino) != (actual.st_dev, actual.st_ino) or ns.st_ino != target["netns"]:
        raise ValueError("network namespace changed")


class Service:
    def __init__(self, state, pins, native):
        self.state = Path(state)
        self.pins = Path(pins)
        self.pins.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.native = native
        self.namespace = NamespacePolicy()
        # A second process must not reconcile or activate against this store.
        # The lease outlives all request/reply connections and never deletes WAL.
        self.lease = os.open(str(state) + ".lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.lease)
            raise
        self.db = sqlite3.connect(state, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS bindings (operation TEXT PRIMARY KEY, association BLOB NOT NULL, target_key TEXT NOT NULL UNIQUE, phase TEXT NOT NULL, proof BLOB, pins TEXT NOT NULL)")
        # A retired record is an immutable operation tombstone, not ownership
        # of a forever-reserved kernel inode. Kernel identities can be reused.
        self.db.execute("UPDATE bindings SET target_key='retired:' || operation WHERE phase='RETIRED'")
        self.db.commit()
        self.lock = threading.RLock()

    def close(self):
        self.db.close()
        os.close(self.lease)

    def row(self, operation):
        return self.db.execute("SELECT association,target_key,phase,proof,pins FROM bindings WHERE operation=?", (operation,)).fetchone()

    def update(self, operation, phase, proof=None):
        with self.db:
            self.db.execute("UPDATE bindings SET phase=?,proof=COALESCE(?,proof) WHERE operation=?", (phase, canonical(proof) if proof is not None else None, operation))
            if phase == "RETIRED":
                self.db.execute("UPDATE bindings SET target_key=? WHERE operation=?", ("retired:"+operation, operation))

    def bound(self, operation, association):
        return dict(operation=operation, binding=identity(association), requirement=identity(association["requirement"]), target=identity(association["target"]))

    def dispatch(self, request, fds):
        exact(request, {"version", "method", "operation", "requirement", "target"})
        if request["version"] != VERSION:
            raise ValueError("unsupported protocol")
        method = request["method"]
        if method == "assess":
            if fds or request["target"] is not None or request["operation"]:
                raise ValueError("assess is advisory, without target or operation")
            try:
                requirement(request["requirement"])
            except (ValueError, TypeError) as error:
                return dict(supported=False, reason=str(error))
            return dict(supported=True)
        if method not in {"activate", "lookup", "retire"}:
            raise ValueError("unknown lifecycle operation")
        operation = request["operation"]
        if type(operation) is not str or not 1 <= len(operation) <= 128:
            raise ValueError("operation required")
        target = request["target"]
        if type(target) is dict and target.get("kind") == "network-interface/v1":
            return self.dispatch_interface(request, fds)
        subtree = type(target) is dict and target.get("kind") == "cgroup-subtree/v1"
        if subtree:
            exact(target, {"kind", "boot", "cgroup", "generation"})
            if type(target["generation"]) is not int or target["generation"] < 1:
                raise ValueError("positive incarnation generation required")
        else:
            exact(target, {"boot", "cgroup", "pid", "start", "netns", "generation"})
        association = dict(requirement=request["requirement"], target=target)
        blob = canonical(association)
        target_key = identity({k: target[k] for k in ["boot", "cgroup"]})
        with self.lock:
            row = self.row(operation)
            if row and bytes(row[0]) != blob:
                raise ValueError("operation cannot change requirement or target")
            if method == "activate":
                if subtree:
                    if len(fds) != 1 or target_identity(fds[0]) != {k: target[k] for k in ["boot", "cgroup"]}:
                        raise ValueError("exact prepared subtree required")
                elif len(fds) != 3:
                    raise ValueError("activation needs cgroup, pidfd and namespace handles")
                plan = requirement(request["requirement"])
                if not subtree:
                    held_target(fds, target)
                if row:
                    if row[2] != "ACTIVE":
                        raise ValueError("uncertain or retiring operation is cleanup-only")
                    self.native.verify(row[4], fds[0], plan.endpoints)
                    return dict(self.bound(operation, association), active=True)
                path = self.pins / hashlib.sha256(operation.encode()).hexdigest()
                with self.db:
                    self.db.execute("INSERT INTO bindings VALUES(?,?,?,?,?,?)", (operation, blob, target_key, "ACTIVATING", None, str(path)))
                proof = self.native.install(path, fds[0], plan.endpoints)
                if self.native.verify(path, fds[0], plan.endpoints) != proof:
                    raise ValueError("independent native readback changed")
                if not subtree:
                    held_target(fds, target)
                self.update(operation, "ACTIVE", proof)
                return dict(self.bound(operation, association), active=True)
            if method == "retire" and row and row[2] in {"EMPTY_CONFIRMED", "RETIRED"}:
                # Durable cleanup-only authority: never lookup, activate or release.
                # Stable emptiness was confirmed before any restriction removal.
                self.remove(row)
                self.update(operation, "RETIRED")
                return dict(self.bound(operation, association), retired=True)
            if len(fds) != 1:
                raise ValueError("lookup/retirement needs exact cgroup handle")
            if target_identity(fds[0]) != {k: target[k] for k in ["boot", "cgroup"]}:
                raise ValueError("exact target changed")
            if method == "lookup":
                if row is None:
                    raise ValueError("unknown operation")
                if row[2] != "ACTIVE":
                    return dict(self.bound(operation, association), active=False, phase=row[2])
                plan = requirement(request["requirement"])
                self.native.verify(row[4], fds[0], plan.endpoints)
                return dict(self.bound(operation, association), active=True, phase=row[2])
            # Stable empty must precede *any* removal, including uncertain installs.
            for _ in range(3):
                if task_ids(fds[0]) or read_events(fds[0]).get("populated") != 0:
                    raise ValueError("retire requires runtime-stopped empty target")
                time.sleep(0.02)
            if row is None:
                path = self.pins / hashlib.sha256(operation.encode()).hexdigest()
                if path.exists():
                    raise ValueError("unowned pin intent")
                return dict(self.bound(operation, association), retired=True)
            if row[2] != "RETIRED":
                self.update(operation, "EMPTY_CONFIRMED")
                self.remove(row)
                self.update(operation, "RETIRED")
            return dict(self.bound(operation, association), retired=True)

    def interface_target(self, fds, target):
        if len(fds) != 2:
            raise ValueError("interface binding requires exact cgroup and netns handles")
        exact(target, {"kind", "boot", "cgroup", "netns", "interface", "generation"})
        exact(target["netns"], {"dev", "ino", "locator"})
        exact(target["interface"], {"index", "name", "address"})
        if type(target["generation"]) is not int or target["generation"] < 1:
            raise ValueError("positive incarnation generation required")
        if target_identity(fds[0]) != {k: target[k] for k in ["boot", "cgroup"]}:
            raise ValueError("interface compute ownership changed")
        locator = target["netns"]["locator"]
        if type(locator) is not str or str(Path(locator).parent) != "/run/netns" or Path(locator).name in {".", ".."}:
            raise ValueError("stable namespace locator required")
        located = os.open(locator, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            observed = os.fstat(located)
            if (observed.st_dev, observed.st_ino) != (target["netns"]["dev"], target["netns"]["ino"]):
                raise ValueError("namespace locator does not identify received handle")
        finally:
            os.close(located)
        ns = os.fstat(fds[1])
        if dict(dev=ns.st_dev, ino=ns.st_ino) != {k: target["netns"][k] for k in ["dev", "ino"]}:
            raise ValueError("exact network namespace changed")
        if self.namespace.interface(fds[1], target["interface"]["name"]) != target["interface"]:
            raise ValueError("exact network interface changed")

    def dispatch_interface(self, request, fds):
        target = request["target"]
        operation, method = request["operation"], request["method"]
        association = dict(requirement=request["requirement"], target=target)
        blob = canonical(association)
        # A host interface cannot observe guest-internal loopback or traffic on
        # other guest interfaces. Never turn a partial ceiling into authority.
        # Existing records and kernel restrictions remain available for exact
        # stopped-target retirement; refusing activation must not erase them.
        if method == "activate":
            raise ValueError("interface-only target cannot enforce complete guest network ceiling")
        # Validation may have rejected activation before any durable binding.
        # Retirement of that attempt is absence-only, never policy acceptance:
        # authenticate live handles, require stable empty compute, independently
        # inspect the operation's exact table, and seal a cleanup-only tombstone.
        # Never remove an unknown table or infer absence from an RPC error.
        with self.lock:
            prior = self.row(operation)
            if method == "retire" and prior is None:
                self.interface_target(fds, target)
                for _ in range(3):
                    if task_ids(fds[0]) or read_events(fds[0]).get("populated") != 0:
                        raise ValueError("retire requires runtime-stopped empty target")
                    time.sleep(0.02)
                tables = self.namespace.run(fds[1], ["list", "tables"])
                inventory = NamespacePolicy.listed_tables(tables)
                table = self.namespace.name(operation)
                if any(x['family'] in {"netdev", "inet"} and x['name'] == table for x in inventory):
                    raise ValueError("unknown interface operation has native residue")
                key = identity(dict(boot=target["boot"], netns={k: target["netns"][k] for k in ["dev", "ino"]}, interface=target["interface"]))
                with self.db:
                    self.db.execute("INSERT INTO bindings VALUES(?,?,?,?,?,?)",
                        (operation, blob, "retired:"+operation, "RETIRED", None, "netdev:"+table))
                return dict(self.bound(operation, association), retired=True)
            if prior is not None and bytes(prior[0]) != blob:
                raise ValueError("operation cannot change requirement or target")
            if method == "retire" and prior is not None and prior[2] == "RETIRED" and prior[3] is None:
                # This tombstone never installed restrictions and is permanently
                # cleanup-only. Exact association is checked above, even on retry.
                return dict(self.bound(operation, association), retired=True)
        plan = requirement(request["requirement"])
        interface = target.get("interface", {}).get("name")
        # Durable empty/retired ownership can finish exact cleanup after the
        # runtime has deleted its cgroup. Reopen only the namespace locator
        # previously authenticated against an SCM_RIGHTS descriptor; it is a
        # locator, never authorization by pathname.
        with self.lock:
            prior = self.row(operation)
            if prior is not None and bytes(prior[0]) != blob:
                raise ValueError("operation cannot change requirement or target")
            if method == "retire" and prior is not None and prior[2] in {"EMPTY_CONFIRMED", "RETIRED"} and len(fds) == 0:
                locator = target.get("netns", {}).get("locator")
                if type(locator) is not str or not locator.startswith("/run/netns/"):
                    raise ValueError("durable cleanup namespace locator unavailable")
                fd = os.open(locator, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    ns = os.fstat(fd)
                    if (ns.st_dev, ns.st_ino) != (target["netns"]["dev"], target["netns"]["ino"]):
                        raise ValueError("cleanup namespace identity changed")
                    table = self.namespace.name(operation)
                    tables = self.namespace.run(fd, ["list", "tables"])
                    present = any(x['family'] in {"netdev", "inet"} and x['name'] == table for x in NamespacePolicy.listed_tables(tables))
                    if present:
                        self.namespace.remove(fd, operation, interface, plan.endpoints)
                finally:
                    os.close(fd)
                self.update(operation, "RETIRED")
                return dict(self.bound(operation, association), retired=True)
        # The runtime owns VM create/restore suspension. This backend protects
        # its exclusive network interface before the runtime releases compute.
        # No guest kernel/cgroup claim and no per-runtime orchestration exist.
        self.interface_target(fds, target)
        key = identity(dict(boot=target["boot"], netns={k: target["netns"][k] for k in ["dev", "ino"]}, interface=target["interface"]))
        plan = requirement(request["requirement"])
        interface = target["interface"]["name"]
        with self.lock:
            row = self.row(operation)
            if row and bytes(row[0]) != blob:
                raise ValueError("operation cannot change requirement or target")
            if row is None:
                # Unlike a guessed table deletion, unknown binding is not proof.
                raise ValueError("unknown interface operation")
            if method == "lookup":
                if row[2] == "ACTIVE":
                    self.namespace.verify(fds[1], operation, interface, plan.endpoints)
                # Historical ACTIVE interface state is restriction evidence,
                # not complete-policy release authority. Keep the record and
                # restrictions intact until runtime-owned stop and retirement.
                return dict(self.bound(operation, association), active=False,
                            phase=row[2], reason="interface-only target cannot enforce complete guest network ceiling")
            # Stop is runtime owned; only stable empty compute permits removal.
            if row[2] != "RETIRED":
                for _ in range(3):
                    if task_ids(fds[0]) or read_events(fds[0]).get("populated") != 0:
                        raise ValueError("retire requires runtime-stopped empty target")
                    time.sleep(0.02)
                if row[2] != "EMPTY_CONFIRMED":
                    self.update(operation, "EMPTY_CONFIRMED")
                # If the atomic transaction was already deleted, independently
                # verify absence. Other errors remain explicit and retryable.
                tables = self.namespace.run(fds[1], ["list", "tables"])
                present = any(x['family'] in {"netdev", "inet"} and
                    x['name'] == self.namespace.name(operation)
                    for x in NamespacePolicy.listed_tables(tables))
                if present:
                    self.namespace.remove(fds[1], operation, interface, plan.endpoints)
                self.update(operation, "RETIRED")
            return dict(self.bound(operation, association), retired=True)

    def remove(self, row):
        path = Path(row[4])
        if path.parent != self.pins:
            raise ValueError("pin owner changed")
        proof = json.loads(row[3]) if row[3] else None
        expected = {"endpoints", "targets"} | {n + suffix for n in self.native.PROGRAMS for suffix in ["-prog", "-link"]}
        if path.exists():
            if not {p.name for p in path.iterdir()} <= expected:
                raise ValueError("foreign pin blocks retirement")
            if proof:
                for kind, objects in [("map", proof["maps"]), ("link", proof["links"]), ("prog", proof["programs"])]:
                    for name, obj in objects.items():
                        pin = path / (name if kind == "map" else name + "-" + kind)
                        if pin.exists() and self.native.info(kind, pin)["id"] != obj["id"]:
                            raise ValueError("pin identity changed")
            for pin in sorted(path.iterdir(), key=lambda p: 0 if p.name.endswith("-link") else 1):
                pin.unlink()
            path.rmdir()
        if proof:
            # Kernel object release can be RCU-delayed; bounded retries do not
            # weaken the independent exact-ID absence requirement.
            deadline = time.monotonic() + 5
            while True:
                live = []
                for kind, objects in [("map", proof["maps"]), ("link", proof["links"]), ("prog", proof["programs"])]:
                    for obj in objects.values():
                        if self.native.object_exists(kind, obj["id"]):
                            live.append((kind, obj["id"]))
                if not live:
                    break
                if time.monotonic() >= deadline:
                    raise ValueError("native object residue remains: " + repr(live))
                time.sleep(0.05)



def bind_owned_socket(sock, address):
    """Recover only a dead root socket in a protected directory, under state lock."""
    path = Path(address)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError("root-owned protected socket directory required")
    try:
        old = path.lstat()
    except FileNotFoundError:
        old = None
    if old is not None:
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != 0 or old.st_mode & 0o077:
            raise ValueError("foreign socket address blocks restart")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as probe:
            probe.settimeout(1)
            try:
                probe.connect(address)
            except OSError as error:
                if error.errno != errno.ECONNREFUSED:
                    raise ValueError("socket liveness uncertain; refusing replacement") from error
            else:
                raise ValueError("live socket blocks restart")
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_uid, current.st_mode) != (old.st_dev, old.st_ino, old.st_uid, old.st_mode):
            raise ValueError("socket address changed during restart")
        path.unlink()
    sock.bind(address)
    os.chmod(address, 0o600)
    return path.lstat()


def serve(config):
    """Root-only caller authentication and descriptor transfer; one normal daemon."""
    exact(config, {"socket", "state", "pins", "object"})
    service = Service(config["state"], config["pins"], Native(config["object"]))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        bound = bind_owned_socket(sock, config["socket"])
    except Exception:  # AUDITED: BROAD — failed admission must release database lock and socket
        sock.close()
        service.close()
        raise
    sock.listen(32)
    sock.settimeout(0.25)
    stopping = threading.Event()
    def stop(_signal, _frame):
        stopping.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping.is_set():
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                continue
            with conn:
                fds = []
                try:
                    conn.settimeout(10)
                    _pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != 0:
                        raise PermissionError("root runtime peer required")
                    data, ancillary, flags, _ = conn.recvmsg(MAX_FRAME, socket.CMSG_SPACE(3 * 4))
                    for level, kind, value in ancillary:
                        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                            raise ValueError("unexpected ancillary authority")
                        handles = array.array("i")
                        handles.frombytes(value)
                        fds.extend(handles)
                    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                        raise ValueError("truncated request")
                    request = json.loads(data)
                    result = service.dispatch(request, fds)
                    reply = dict(version=VERSION, ok=True, result=result)
                except Exception as error:  # AUDITED: BROAD — fail closed at authenticated transport boundary
                    reply = dict(version=VERSION, ok=False, error=str(error))
                finally:
                    for fd in fds:
                        os.close(fd)
                try:
                    conn.send(canonical(reply))
                except OSError:
                    # Lost reply cannot discard durable operation ownership.
                    logging.getLogger(__name__).warning("enforcer reply disconnected", exc_info=True)
    finally:
        sock.close()
        try:
            current = Path(config["socket"]).lstat()
            if (current.st_dev, current.st_ino) != (bound.st_dev, bound.st_ino):
                raise ValueError("socket replaced before shutdown")
            Path(config["socket"]).unlink()
        finally:
            service.close()


def serve_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        st = os.fstat(stream.fileno())
        if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISREG(st.st_mode):
            raise ValueError("root-owned non-writable regular configuration required")
        raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError("configuration too large")
    config = json.loads(raw)
    exact(config, {"socket", "state", "pins", "object"})
    for key, value in config.items():
        if type(value) is not str or not Path(value).is_absolute():
            raise ValueError("absolute trusted configuration paths required: " + key)
    serve(config)
