"""Held-root filesystem identities and isolated, read-back BPF-LSM policies."""
from __future__ import annotations

import json
import os
import stat
import struct

from .native_network import Native
from .policy import OPERATIONS
from .target import validate_cgroup_fd

MAX_IDENTITIES = 8192
MAX_DEPTH = 128
MAX_SNAPSHOT_BYTES = 65536
OPERATION_MASK = sum(1 << (n + 1) for n in range(len(OPERATIONS)))


def inode_identity(fd):
    observed = os.fstat(fd)
    # inode->i_sb->s_dev uses the kernel's MINORBITS=20 encoding.
    return [(os.major(observed.st_dev) << 20) | os.minor(observed.st_dev),
            observed.st_ino, stat.S_IFMT(observed.st_mode)]


def path_identity(fd):
    observed = os.fstat(fd)
    return [(os.major(observed.st_dev) << 20) | os.minor(observed.st_dev),
            observed.st_ino, observed.st_mode, observed.st_ctime_ns]


def process_start(proc):
    fd = os.open("stat", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=proc)
    with os.fdopen(fd) as stream:
        return stream.read().rsplit(")", 1)[1].split()[19]


class HeldPaths:
    """No host pathname fallback, symlink following, or unbounded tree walk.

    The caller must authenticate ``pid`` using the transferred pidfd first.
    Every inode remains open through installation/readback. The durable
    receiver-local PID/start/root/mount identity permits fail-closed recovery,
    not arbitrary caller PID selection.
    """

    def __init__(self, pid, start, paths):
        self.fds = []
        self.records = {}
        try:
            proc = self.hold(os.open("/proc/" + str(pid), os.O_PATH | os.O_DIRECTORY |
                                     os.O_CLOEXEC | os.O_NOFOLLOW))
            if process_start(proc) != start:
                raise ValueError("filesystem process incarnation changed")
            mount = self.hold(os.open("ns/mnt", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc))
            root = self.hold(os.open("root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
                                     dir_fd=proc))
            self.root = root
            for path in paths:
                self.walk(path)
            if process_start(proc) != start:
                raise ValueError("filesystem process changed during traversal")
            self.spec = dict(pid=pid, start=start, root=inode_identity(root),
                             mount=[os.fstat(mount).st_dev, os.fstat(mount).st_ino],
                             paths=list(paths),
                             entries=[[name, *value] for name, value in sorted(self.records.items())])
            if len(json.dumps(self.spec, ensure_ascii=True).encode()) > MAX_SNAPSHOT_BYTES:
                raise ValueError("protected snapshot exceeds bounded readback size")
        except BaseException:
            self.close()
            raise

    def hold(self, fd):
        self.fds.append(fd)
        return fd

    def walk(self, path):
        parts = path.split("/")[1:]
        if (not path.startswith("/") or path.startswith("//") or not parts or
                len(parts) > MAX_DEPTH or len(os.fsencode(path)) > 4096 or
                any(p in {"", ".", ".."} or "\x00" in p for p in parts)):
            raise ValueError("unsupported protected path")
        parent = os.dup(self.root)
        try:
            for part in parts:
                child = os.open(part, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
                if stat.S_ISLNK(os.fstat(parent).st_mode):
                    raise ValueError("protected path symlinks are unsupported")
            self.hold(parent)
            parent = None
            self.visit(path, self.fds[-1], len(parts))
        finally:
            if parent is not None:
                os.close(parent)

    def visit(self, path, fd, depth):
        if path in self.records:
            if self.records[path] != path_identity(fd):
                raise ValueError("overlapping protected path changed")
            return
        if len(self.records) >= MAX_IDENTITIES or depth > MAX_DEPTH:
            raise ValueError("protected tree exceeds bounded traversal")
        observed = path_identity(fd)
        if stat.S_IFMT(observed[2]) not in {stat.S_IFREG, stat.S_IFDIR}:
            raise ValueError("protected tree must contain only regular files and directories")
        self.records[path] = observed
        if stat.S_IFMT(observed[2]) == stat.S_IFDIR:
            listing = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
            try:
                with os.scandir(listing) as entries:
                    for entry in entries:
                        child = self.hold(os.open(entry.name, os.O_PATH | os.O_NOFOLLOW |
                                                 os.O_CLOEXEC, dir_fd=fd))
                        self.visit(path + "/" + entry.name, child, depth + 1)
            finally:
                os.close(listing)

    def check(self):
        with HeldPaths(self.spec["pid"], self.spec["start"], self.spec["paths"]) as current:
            if current.spec != self.spec:
                raise ValueError("held filesystem root or protected identities changed")

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class FilesystemNative(Native):
    HOOKS = {
        "deny_writable_open": "file_open", "deny_write": "file_permission",
        "deny_truncate": "path_truncate", "deny_create": "inode_create",
        "deny_mkdir": "inode_mkdir", "deny_mknod": "inode_mknod",
        "deny_link": "inode_link", "deny_metadata": "inode_setattr",
        "deny_setxattr": "inode_setxattr", "deny_removexattr": "inode_removexattr",
        "deny_rename": "inode_rename", "deny_symlink": "inode_symlink",
        "deny_unlink": "inode_unlink", "deny_rmdir": "inode_rmdir",
        "deny_mount_bypass": "sb_mount",
    }
    PROGRAMS = {name: ("lsm", None) for name in HOOKS}
    MAPS = {
        "guarded_targets": ("hash", 8, 8, 4096),
        "guarded_paths": ("hash", 24, 8, 131072),
        # Kernel-produced telemetry is not policy; ring buffers cannot freeze.
        "filesystem_denials": ("ringbuf", 0, 0, 1 << 20),
    }

    def entries(self, cgroup, spec):
        cg = validate_cgroup_fd(cgroup)
        return {
            "guarded_targets": {struct.pack("=Q", cg.cgroup_id): struct.pack("=Q", spec["generation"])},
            "guarded_paths": {
                struct.pack("=QQQ", spec["generation"], device, inode): struct.pack("=II", OPERATION_MASK, 0)
                for _, device, inode, _, _ in spec["entries"]
            },
        }

    def verify(self, directory, cgroup, spec):
        proof = super().verify(directory, cgroup, spec)
        owned = {m["id"] for m in proof["maps"].values()}
        if any(set(p.get("map_ids", [])) != owned for p in proof["programs"].values()):
            raise ValueError("filesystem program policy-map ownership mismatch")
        if len({p["id"] for p in proof["programs"].values()}) != len(self.PROGRAMS):
            raise ValueError("duplicate filesystem programs")
        return dict(proof, filesystem=spec)
