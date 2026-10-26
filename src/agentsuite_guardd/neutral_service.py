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
from .container_policy import ContainerPlan, FORMAT as CONTAINER_FORMAT, compile_container
from .policy import compile_policy, BackendPlan
from .model import CAPABILITY
from .target import boot_id, validate_cgroup_fd, cgroup_removed, task_ids, read_events, TargetNotLive
from .native_network import Native
from .native_filesystem import FilesystemNative, HeldPaths
from .native_container import ContainerNative
from .namespace_policy import NamespacePolicy
from .config import load_root_json

VERSION = "execution-enforcement/v1"
MAX_FRAME = 1048576


class TargetNotStopped(ValueError):
    """The runtime has not completed its physical stop fence."""


def checked_reply(result, limit=MAX_FRAME):
    reply = canonical(dict(version=VERSION, ok=True, result=result))
    if len(reply) > limit:
        raise ValueError("complete enforcement evidence exceeds transport reply capacity")
    return reply


def seqpacket_reply_limit(conn):
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, MAX_FRAME + 32)
    # Linux rejects a seqpacket larger than sk_sndbuf - 32. SO_SNDBUF may
    # be clamped, so a requested size alone is not a transport guarantee.
    return min(MAX_FRAME, conn.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) - 32)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identity(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("complete exact fields required: " + ",".join(sorted(keys)))


def requirement(value):
    exact(value, {"format", "bytes", "digest", "capabilities"})
    raw = base64.b64decode(value["bytes"], validate=True)
    if value["format"] == CONTAINER_FORMAT:
        return compile_container(raw, value["digest"], value["capabilities"])
    if value["format"] == "agentsuite.policy/v2":
        return compile_network(raw, value["digest"], value["capabilities"])
    if value["format"] == "agentsuite.policy/v1":
        if value["capabilities"] != [CAPABILITY]:
            raise ValueError("unsupported complete filesystem capabilities")
        return compile_policy(raw, value["digest"], "held-native")
    raise ValueError("unsupported complete policy format")


def target_identity(fd, *, allow_deleted=False):
    return dict(boot=boot_id(),
                cgroup=validate_cgroup_fd(fd, allow_deleted=allow_deleted).dict())


def same_cgroup_object(actual, expected):
    """An observer may open the exact cgroup through another cgroupfs mount."""
    keys = {"dev", "ino", "mount_id", "cgroup_id"}
    for value in (actual, expected):
        if type(value) is not dict or set(value) != {"boot", "cgroup"}:
            return False
        cg = value["cgroup"]
        if type(cg) is not dict or set(cg) != keys:
            return False
        if any(type(cg[key]) is not int or cg[key] < (0 if key == "dev" else 1) for key in keys):
            return False
    return actual["boot"] == expected["boot"] and all(
        actual["cgroup"][key] == expected["cgroup"][key]
        for key in ("dev", "ino", "cgroup_id"))


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
    if pid <= 0:
        raise TargetNotLive("live pidfd namespace identity required")
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
    if target["start"] != start:
        raise ValueError("held target membership/start mismatch")
    members = task_ids(fds[0])
    if pid not in members:
        raise TargetNotLive("held target membership/start mismatch")
    if members != [pid]:
        raise ValueError("held target membership/start mismatch")
    ns = os.fstat(fds[2])
    actual = os.stat("/proc/" + str(pid) + "/ns/net")
    if (ns.st_dev, ns.st_ino) != (actual.st_dev, actual.st_ino) or ns.st_ino != target["netns"]:
        raise ValueError("network namespace changed")
    return pid


def filesystem_spec(held, target, plan):
    spec = dict(held.spec, generation=target["generation"])
    if isinstance(plan, ContainerPlan):
        spec["network"] = [list(endpoint) for endpoint in plan.endpoints]
    return spec


class Service:
    def __init__(self, state, pins, native, filesystem=None, container=None):
        self.state = Path(state)
        self.pins = Path(pins)
        self.pins.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.native = native
        self.filesystem = filesystem
        self.container = container
        self.held_paths = {}
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
        for held in self.held_paths.values():
            held.close()
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

    def backend(self, requirement):
        if requirement["format"] == CONTAINER_FORMAT:
            return self.container
        if requirement["format"] == "agentsuite.policy/v1":
            return self.filesystem
        return self.native

    def dispatch(self, request, fds, *, reply_limit=MAX_FRAME, verified_stopped=False):
        exact(request, {"version", "method", "operation", "requirement", "target"})
        if request["version"] != VERSION:
            raise ValueError("unsupported protocol")
        method = request["method"]
        if method == "assess":
            if fds or request["target"] is not None or request["operation"]:
                raise ValueError("assess is advisory, without target or operation")
            try:
                plan = requirement(request["requirement"])
                if self.backend(request["requirement"]) is None:
                    raise ValueError("required native BPF object is not configured")
            except (ValueError, TypeError) as error:
                return dict(supported=False, reason=str(error))
            return dict(supported=True)
        if method not in {"activate", "lookup", "retire"}:
            raise ValueError("unknown lifecycle operation")
        operation = request["operation"]
        if type(operation) is not str or not 1 <= len(operation) <= 128:
            raise ValueError("operation required")
        target = request["target"]
        exact(request["requirement"], {"format", "bytes", "digest", "capabilities"})
        filesystem = request["requirement"].get("format") in {"agentsuite.policy/v1", CONTAINER_FORMAT}
        if filesystem and type(target) is dict and "kind" in target:
            raise ValueError("filesystem enforcement requires a held-native target")
        if type(target) is dict and target.get("kind") == "network-interface/v1":
            return self.dispatch_interface(request, fds)
        subtree = type(target) is dict and target.get("kind") == "cgroup-subtree/v1"
        if subtree:
            exact(target, {"kind", "boot", "cgroup", "generation"})
            if type(target["generation"]) is not int or target["generation"] < 1:
                raise ValueError("positive incarnation generation required")
        else:
            exact(target, {"boot", "cgroup", "pid", "start", "netns", "generation"})
        if filesystem and (type(target["generation"]) is not int or
                           not 1 <= target["generation"] <= 0xffffffffffffffff):
            raise ValueError("filesystem generation must be a positive uint64")
        association = dict(requirement=request["requirement"], target=target)
        blob = canonical(association)
        target_key = identity({k: target[k] for k in ["boot", "cgroup"]})
        with self.lock:
            row = self.row(operation)
            if row and bytes(row[0]) != blob:
                raise ValueError("operation cannot change requirement or target")
            if (method == "retire" and row is not None
                    and target["boot"] != boot_id()):
                path = Path(row[4])
                if path.parent != self.pins or path.exists():
                    raise ValueError("previous-kernel retirement blocked by current pin ownership")
                # BPF links and processes cannot survive a kernel boot. Old
                # numeric object IDs may now name unrelated current objects.
                if operation in self.held_paths:
                    self.held_paths.pop(operation).close()
                self.update(operation, "RETIRED")
                return dict(self.bound(operation, association), retired=True)
            if method == "activate":
                if subtree:
                    if len(fds) != 1 or target_identity(fds[0]) != {k: target[k] for k in ["boot", "cgroup"]}:
                        raise ValueError("exact prepared subtree required")
                elif len(fds) != 3:
                    raise ValueError("activation needs cgroup, pidfd and namespace handles")
                plan = requirement(request["requirement"])
                backend = self.backend(request["requirement"])
                if backend is None:
                    raise ValueError("filesystem BPF object is not configured")
                if not subtree:
                    pid = held_target(fds, target)
                if row:
                    if row[2] != "ACTIVE":
                        raise ValueError("uncertain or retiring operation is cleanup-only")
                    if filesystem:
                        proof = json.loads(row[3])
                        current = HeldPaths(pid, target["start"], plan.deny_write_paths)
                        try:
                            spec = filesystem_spec(current, target, plan)
                            if proof.get("filesystem") != spec:
                                raise ValueError("filesystem identity changed on retry")
                            if backend.verify(row[4], fds[0], spec) != proof:
                                raise ValueError("filesystem kernel ownership changed")
                            current.check()
                            held_target(fds, target)
                            if operation not in self.held_paths:
                                self.held_paths[operation] = current
                        finally:
                            if self.held_paths.get(operation) is not current:
                                current.close()
                    else:
                        self.native.verify(row[4], fds[0], plan.endpoints)
                    if filesystem:
                        checked_reply(dict(self.bound(operation, association), active=True,
                                           phase="ACTIVE", readback=proof), reply_limit)
                    return dict(self.bound(operation, association), active=True)
                path = self.pins / hashlib.sha256(operation.encode()).hexdigest()
                held = HeldPaths(pid, target["start"], plan.deny_write_paths) if filesystem else None
                intent = dict(filesystem=filesystem_spec(held, target, plan)) if held else None
                try:
                    if held:
                        checked_reply(dict(self.bound(operation, association), active=True,
                                           phase="ACTIVE", readback=intent), reply_limit)
                    with self.db:
                        self.db.execute("INSERT INTO bindings VALUES(?,?,?,?,?,?)", (operation, blob, target_key, "ACTIVATING", canonical(intent) if intent else None, str(path)))
                except BaseException:
                    if held:
                        held.close()
                    raise
                if held:
                    # Retain identities even if installation/readback fails.
                    self.held_paths[operation] = held
                payload = intent["filesystem"] if filesystem else plan.endpoints
                proof = backend.install(path, fds[0], payload)
                # Persist kernel ownership before the independent verification:
                # a later failure is still cleanup-only, with exact IDs retained.
                self.update(operation, "ACTIVATING", proof)
                if backend.verify(path, fds[0], payload) != proof:
                    raise ValueError("independent native readback changed")
                if held:
                    held.check()
                if not subtree:
                    held_target(fds, target)
                checked_reply(dict(self.bound(operation, association), active=True,
                                   phase="ACTIVE", readback=proof), reply_limit)
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
            actual = target_identity(fds[0], allow_deleted=True) if method == "retire" else target_identity(fds[0])
            expected = {k: target[k] for k in ["boot", "cgroup"]}
            if actual != expected:
                # Only filesystem observation accepts another mount view of
                # the same live kernel cgroup. The immutable association and
                # authenticated process/root/mount snapshot remain exact.
                # The recovery flag is trusted in-process adapter authority,
                # never a wire field. It requires durable independent runtime
                # stop proof; the exact kernel identity and empty fence remain.
                mount_alias = method == "lookup" or (method == "retire" and verified_stopped)
                if not (filesystem and mount_alias and same_cgroup_object(actual, expected)):
                    raise ValueError("exact target changed")
            if method == "lookup":
                if row is None:
                    raise ValueError("unknown operation")
                if row[2] != "ACTIVE":
                    return dict(self.bound(operation, association), active=False, phase=row[2])
                plan = requirement(request["requirement"])
                if filesystem:
                    backend = self.backend(request["requirement"])
                    if backend is None:
                        raise ValueError("required native BPF object is not configured")
                    proof = json.loads(row[3])
                    spec = proof["filesystem"]
                    # Receiver-local PID/start was bound from a live pidfd at
                    # activation, never from the caller's numeric PID.
                    if spec["pid"] not in task_ids(fds[0]):
                        raise TargetNotLive("filesystem root process no longer belongs to target")
                    current = HeldPaths(spec["pid"], spec["start"], plan.deny_write_paths)
                    try:
                        if filesystem_spec(current, target, plan) != spec:
                            raise ValueError("filesystem identities changed since activation")
                        observed = backend.verify(row[4], fds[0], spec)
                        if observed != proof:
                            raise ValueError("filesystem kernel ownership changed")
                        current.check()
                        if spec["pid"] not in task_ids(fds[0]):
                            raise TargetNotLive("filesystem root process left target during readback")
                        if operation not in self.held_paths:
                            self.held_paths[operation] = current
                    finally:
                        if self.held_paths.get(operation) is not current:
                            current.close()
                    return dict(self.bound(operation, association), active=True,
                                phase=row[2], readback=observed)
                else:
                    self.native.verify(row[4], fds[0], plan.endpoints)
                return dict(self.bound(operation, association), active=True, phase=row[2])
            # Stable empty must precede *any* removal, including uncertain installs.
            for _ in range(3):
                if cgroup_removed(fds[0]):
                    break
                try:
                    populated = task_ids(fds[0]) or read_events(fds[0]).get("populated") != 0
                except FileNotFoundError:
                    if not cgroup_removed(fds[0]):
                        raise
                    break
                if populated:
                    raise TargetNotStopped("retire requires runtime-stopped empty target")
                time.sleep(0.02)
            if row is None:
                path = self.pins / hashlib.sha256(operation.encode()).hexdigest()
                if path.exists():
                    raise ValueError("unowned pin intent")
                with self.db:
                    self.db.execute(
                        "INSERT INTO bindings VALUES(?,?,?,?,?,?)",
                        (operation, blob, "retired:" + operation, "RETIRED", None, str(path)),
                    )
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
        stored_requirement = json.loads(row[0])["requirement"]
        filesystem = stored_requirement["format"] in {"agentsuite.policy/v1", CONTAINER_FORMAT}
        backend = self.backend(stored_requirement)
        if backend is None:
            raise ValueError("filesystem BPF object is required for cleanup")
        maps = set(backend.MAPS) if hasattr(backend, "MAPS") else {"endpoints", "targets"}
        expected = maps | {n + suffix for n in backend.PROGRAMS for suffix in ["-prog", "-link"]}
        operation = self.db.execute("SELECT operation FROM bindings WHERE pins=?", (str(path),)).fetchone()
        if path.exists():
            if not {p.name for p in path.iterdir()} <= expected:
                raise ValueError("foreign pin blocks retirement")
            if proof and "maps" in proof:
                for kind, objects in [("map", proof["maps"]), ("link", proof["links"]), ("prog", proof["programs"])]:
                    for name, obj in objects.items():
                        pin = path / (name if kind == "map" else name + "-" + kind)
                        if pin.exists() and backend.info(kind, pin)["id"] != obj["id"]:
                            raise ValueError("pin identity changed")
            if filesystem and (not proof or "maps" not in proof):
                # An install may have failed before complete readback. Only
                # after EMPTY_CONFIRMED, journal the exact partial inventory
                # before unlinking so crash recovery still proves ID absence.
                proof = dict(proof or {}, maps={}, programs={}, links={})
                for pin in path.iterdir():
                    if pin.name.endswith("-prog"):
                        kind, group, name = "prog", "programs", pin.name[:-5]
                    elif pin.name.endswith("-link"):
                        kind, group, name = "link", "links", pin.name[:-5]
                    else:
                        kind, group, name = "map", "maps", pin.name
                    proof[group][name] = backend.info(kind, pin)
                self.update(operation[0], "EMPTY_CONFIRMED", proof)
            for pin in sorted(path.iterdir(), key=lambda p: 0 if p.name.endswith("-link") else 1):
                pin.unlink()
            path.rmdir()
        if proof and "maps" in proof:
            # Kernel object release can be RCU-delayed; bounded retries do not
            # weaken the independent exact-ID absence requirement.
            deadline = time.monotonic() + 5
            while True:
                live = []
                for kind, objects in [("map", proof["maps"]), ("link", proof["links"]), ("prog", proof["programs"])]:
                    for obj in objects.values():
                        if backend.object_exists(kind, obj["id"]):
                            live.append((kind, obj["id"]))
                if not live:
                    break
                if time.monotonic() >= deadline:
                    raise ValueError("native object residue remains: " + repr(live))
                time.sleep(0.05)
        if operation and operation[0] in self.held_paths:
            self.held_paths.pop(operation[0]).close()



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
    validate_config(config)
    filesystem = FilesystemNative(config["filesystemObject"]) if "filesystemObject" in config else None
    container = ContainerNative(config["containerObject"]) if "containerObject" in config else None
    service = Service(config["state"], config["pins"], Native(config["object"]), filesystem, container)
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
                    reply_limit = seqpacket_reply_limit(conn)
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
                    result = service.dispatch(request, fds, reply_limit=reply_limit)
                    reply = checked_reply(result, reply_limit)
                except Exception as error:  # AUDITED: BROAD — fail closed at authenticated transport boundary
                    reply = canonical(dict(version=VERSION, ok=False, error=str(error)[:2048]))
                finally:
                    for fd in fds:
                        os.close(fd)
                try:
                    conn.send(reply)
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
    config = load_root_json(path)
    validate_config(config)
    serve(config)


def validate_config(config):
    required = {"socket", "state", "pins", "object"}
    if (type(config) is not dict or not required <= set(config)
            or not set(config) <= required | {"filesystemObject", "containerObject"}):
        raise ValueError("exact neutral configuration fields required")
    for key, value in config.items():
        if type(value) is not str or not Path(value).is_absolute():
            raise ValueError("absolute trusted configuration paths required: " + key)
