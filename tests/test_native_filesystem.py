"""Real local FD traversal and deterministic readback tests, not kernel acceptance."""
import os
import ctypes as C
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agentsuite_guardd.native_filesystem import (
    FilesystemNative, HeldPaths, OPERATION_MASK, inode_identity,
)
from agentsuite_guardd.native_network import Native


def start():
    return Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]


def test_real_proc_root_holds_original_inodes_and_detects_replacement(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    canary = protected / "canary"
    canary.write_text("original")
    with HeldPaths(os.getpid(), start(), [str(protected)]) as held:
        records = {r[0]: r[1:] for r in held.spec["entries"]}
        assert set(records) == {str(protected), str(canary)}
        assert records[str(canary)][1] == canary.stat().st_ino
        held.check()
        original_inode = canary.stat().st_ino
        canary.unlink()
        canary.write_text("replacement")
        assert any(os.fstat(fd).st_ino == original_inode for fd in held.fds)
        with pytest.raises(ValueError, match="identities changed"):
            held.check()
    assert held.fds == []


def test_resolve_relative_to_received_process_root_not_host_path(tmp_path):
    runtime = tmp_path / "runtime"
    host = tmp_path / "host"
    runtime.mkdir()
    host.mkdir()
    (runtime / "same-name").write_text("runtime")
    (host / "same-name").write_text("host")
    proc = tmp_path / "proc"
    (proc / "ns").mkdir(parents=True)
    (proc / "stat").write_text("4242 (held) " + " ".join(["0"] * 19 + ["500"]))
    (proc / "root").symlink_to(runtime)
    (proc / "ns/mnt").symlink_to("/proc/self/ns/mnt")
    original_open = os.open
    absolute_opens = []

    def opened(path, *args, **kwargs):
        if isinstance(path, str) and path.startswith("/"):
            absolute_opens.append(path)
        return original_open(str(proc) if path == "/proc/4242" else path, *args, **kwargs)

    with patch("agentsuite_guardd.native_filesystem.os.open", side_effect=opened):
        with HeldPaths(4242, "500", ["/same-name"]) as held:
            assert held.spec["entries"][0][2] == (runtime / "same-name").stat().st_ino
            assert held.spec["entries"][0][2] != (host / "same-name").stat().st_ino
            assert held.spec["root"][1] == runtime.stat().st_ino
    assert absolute_opens == ["/proc/4242"]


@pytest.mark.parametrize("path", ["/", "//etc", "/a/../b", "/a//b", "/a/.", "/a/", "relative", "/a\0b"])
def test_non_normal_protected_paths_refuse(path):
    with pytest.raises(ValueError, match="unsupported protected path"):
        HeldPaths(os.getpid(), start(), [path])


@pytest.mark.parametrize("where", ["root", "intermediate", "descendant"])
def test_symlinks_never_followed(tmp_path, where):
    real = tmp_path / "real"
    real.mkdir()
    (real / "canary").write_text("original")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    if where == "descendant":
        protected = real
        (real / "escape").symlink_to(tmp_path)
    else:
        protected = link if where == "root" else link / "canary"
    with pytest.raises(ValueError, match="symlinks|only regular"):
        HeldPaths(os.getpid(), start(), [str(protected)])
    assert (real / "canary").read_text() == "original"


def test_missing_path_and_special_file_refuse(tmp_path):
    with pytest.raises(FileNotFoundError):
        HeldPaths(os.getpid(), start(), [str(tmp_path / "missing")])
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="only regular"):
        HeldPaths(os.getpid(), start(), [str(fifo)])


def test_tree_count_and_depth_are_bounded(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "a").write_text("a")
    (protected / "b").write_text("b")
    with patch("agentsuite_guardd.native_filesystem.MAX_IDENTITIES", 2):
        with pytest.raises(ValueError, match="bounded traversal"):
            HeldPaths(os.getpid(), start(), [str(protected)])
    with patch("agentsuite_guardd.native_filesystem.MAX_SNAPSHOT_BYTES", 16):
        with pytest.raises(ValueError, match="bounded readback"):
            HeldPaths(os.getpid(), start(), [str(protected)])
    with patch("agentsuite_guardd.native_filesystem.MAX_DEPTH", 1):
        with pytest.raises(ValueError, match="unsupported protected path"):
            HeldPaths(os.getpid(), start(), [str(protected)])


def test_start_identity_and_protected_mode_changes_fail_closed(tmp_path):
    path = tmp_path / "canary"
    path.write_text("original")
    with pytest.raises(ValueError, match="incarnation changed"):
        HeldPaths(os.getpid(), "not-this-process", [str(path)])
    with HeldPaths(os.getpid(), start(), [str(path)]) as held:
        before = path.stat()
        path.chmod(0o600 if before.st_mode & 0o077 else 0o644)
        with pytest.raises(ValueError, match="identities changed"):
            held.check()


def test_native_map_encoding_is_exact_and_includes_every_operation(tmp_path):
    path = tmp_path / "canary"
    path.write_text("original")
    native = FilesystemNative.__new__(FilesystemNative)
    with HeldPaths(os.getpid(), start(), [str(path)]) as held:
        spec = dict(held.spec, generation=7)
        with patch("agentsuite_guardd.native_filesystem.validate_cgroup_fd", return_value=SimpleNamespace(cgroup_id=123)):
            entries = native.entries(99, spec)
        fd = os.open(path, os.O_PATH)
        try:
            device, inode, _ = inode_identity(fd)
        finally:
            os.close(fd)
    assert entries == {
        "guarded_targets": {struct.pack("=Q", 123): struct.pack("=Q", 7)},
        "guarded_paths": {struct.pack("=QQQ", 7, device, inode): struct.pack("=II", OPERATION_MASK, 0)},
    }


@pytest.mark.parametrize("mutation", ["foreign-map", "missing-map", "duplicate-program"])
def test_filesystem_program_ownership_readback_refuses(mutation):
    native = FilesystemNative.__new__(FilesystemNative)
    proof = dict(maps={"targets": {"id": 1}, "paths": {"id": 2}, "events": {"id": 3}},
                 programs={name: dict(id=n + 10, map_ids=[1, 2, 3])
                           for n, name in enumerate(native.PROGRAMS)}, links={})
    first, second = list(proof["programs"].values())[:2]
    if mutation == "foreign-map":
        first["map_ids"].append(999)
    elif mutation == "missing-map":
        first["map_ids"].remove(2)
    else:
        second["id"] = first["id"]
    with patch.object(Native, "verify", return_value=proof):
        with pytest.raises(ValueError, match="ownership|duplicate"):
            native.verify("unused", 99, {})


@pytest.fixture
def readback(tmp_path):
    """Synthetic bpftool/libbpf metadata, exercising the actual verifier."""
    native = FilesystemNative.__new__(FilesystemNative)
    info = {}
    for n, (name, (kind, key, value, count)) in enumerate(native.MAPS.items(), 1):
        (tmp_path / name).touch()
        info[("map", name)] = dict(id=n, type=kind, bytes_key=key, bytes_value=value,
                                  max_entries=count, flags=0, frozen=kind != "ringbuf")
    btf_types, hook_ids = [], {}
    for n, (name, hook) in enumerate(native.HOOKS.items(), 1):
        for suffix in ("-prog", "-link"):
            (tmp_path / (name + suffix)).touch()
        info[("prog", name + "-prog")] = dict(id=100 + n, type="lsm",
                                             name=name[:15], map_ids=[1, 2, 3])
        info[("link", name + "-link")] = dict(id=200 + n, type="tracing", prog_id=100 + n)
        btf_types.append(dict(id=n, name="bpf_lsm_" + hook))
        hook_ids[name + "-prog"] = n
    spec = dict(generation=7, entries=[["/canary", 8, 9, 32768, 1]])
    with patch("agentsuite_guardd.native_filesystem.validate_cgroup_fd", return_value=SimpleNamespace(cgroup_id=123)):
        encoded = native.entries(99, spec)
    dumps = {name: [dict(key=list(key), value=list(value)) for key, value in entries.items()]
             for name, entries in encoded.items()}
    fd_names = {}

    class Library:
        def bpf_obj_get(self, path):
            fd = os.open("/dev/null", os.O_RDONLY)
            fd_names[fd] = Path(path.decode()).name
            return fd

        def bpf_obj_get_info_by_fd(self, fd, buffer, size):
            C.memmove(C.addressof(buffer) + 220, struct.pack("=II", 0, hook_ids[fd_names[fd]]), 8)
            return 0

    native.lib = Library()
    native.info = lambda kind, path: info[(kind, Path(path).name)]
    native.dump = lambda path: dumps[Path(path).name]
    with patch("agentsuite_guardd.native_network.validate_cgroup_fd", return_value=SimpleNamespace(cgroup_id=123)), \
         patch("agentsuite_guardd.native_filesystem.validate_cgroup_fd", return_value=SimpleNamespace(cgroup_id=123)), \
         patch("agentsuite_guardd.native_network.subprocess.check_output", side_effect=lambda *a, **kw: json.dumps(dict(types=btf_types)).encode()):
        yield native, tmp_path, spec, info, dumps, btf_types


def test_full_verifier_accepts_exact_synthetic_inventory(readback):
    native, directory, spec, info, dumps, btf = readback
    proof = native.verify(directory, 99, spec)
    assert proof["filesystem"] == spec
    assert len(proof["maps"]) == 3
    assert len(proof["programs"]) == len(proof["links"]) == 15


@pytest.mark.parametrize("mutation", [
    "extra-target", "missing-path", "wrong-mask", "unfrozen", "map-abi",
    "wrong-program", "wrong-link", "wrong-hook", "missing-pin", "foreign-pin",
    "extra-program-map", "duplicate-link",
])
def test_full_verifier_rejects_non_exact_synthetic_inventory(readback, mutation):
    native, directory, spec, info, dumps, btf = readback
    if mutation == "extra-target":
        dumps["guarded_targets"].append(dict(key=list(struct.pack("=Q", 999)), value=list(struct.pack("=Q", 7))))
    elif mutation == "missing-path":
        dumps["guarded_paths"].clear()
    elif mutation == "wrong-mask":
        dumps["guarded_paths"][0]["value"] = list(struct.pack("=II", 0, 0))
    elif mutation == "unfrozen":
        info[("map", "guarded_paths")]["frozen"] = False
    elif mutation == "map-abi":
        info[("map", "guarded_targets")]["max_entries"] += 1
    elif mutation == "wrong-program":
        info[("prog", "deny_write-prog")]["name"] = "wrong"
    elif mutation == "wrong-link":
        info[("link", "deny_write-link")]["prog_id"] = 999
    elif mutation == "wrong-hook":
        btf[0]["name"] = "bpf_lsm_wrong"
    elif mutation == "missing-pin":
        (directory / "deny_write-link").unlink()
    elif mutation == "foreign-pin":
        (directory / "foreign").touch()
    elif mutation == "extra-program-map":
        info[("prog", "deny_write-prog")]["map_ids"].append(999)
    else:
        info[("link", "deny_write-link")]["id"] = info[("link", "deny_create-link")]["id"]
    with pytest.raises(ValueError, match="mismatch|duplicate"):
        native.verify(directory, 99, spec)
