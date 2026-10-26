"""Complete verifier behavior for cgroup links disappearing during readback."""
import os
from pathlib import Path
import struct
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agentsuite_guardd.native_network import Native
from agentsuite_guardd.neutral_service import TargetNotLive
from agentsuite_guardd.target import CGROUP2_SUPER_MAGIC, cgroup_removed, validate_cgroup_fd


def test_removed_held_directory_is_typed_lifetime_loss(tmp_path):
    directory = tmp_path / "target"
    directory.mkdir()
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with patch("agentsuite_guardd.target._filesystem_magic", return_value=CGROUP2_SUPER_MAGIC):
            before = validate_cgroup_fd(fd)
            directory.rmdir()
            with pytest.raises(TargetNotLive):
                validate_cgroup_fd(fd)
            assert cgroup_removed(fd)
            assert validate_cgroup_fd(fd, allow_deleted=True) == before
    finally:
        os.close(fd)


@pytest.fixture
def cgroup_readback(tmp_path):
    native = Native.__new__(Native)
    native.PROGRAMS = {"connect4": ("cgroup", 10)}
    info = {}
    for index, (name, (kind, key, value, count)) in enumerate(native.MAPS.items(), 1):
        (tmp_path / name).touch()
        info["map", name] = dict(
            id=index, type=kind, bytes_key=key, bytes_value=value,
            max_entries=count, flags=0, frozen=1,
        )
    for suffix in ("-prog", "-link"):
        (tmp_path / ("connect4" + suffix)).touch()
    info["prog", "connect4-prog"] = dict(id=100, name="connect4", map_ids=[1, 2])
    link = dict(id=200, type="cgroup", prog_id=100, cgroup_id=123,
                attach_type="cgroup_inet4_connect")
    info["link", "connect4-link"] = link
    native.lib = SimpleNamespace(bpf_obj_get=lambda _path: os.open("/dev/null", os.O_RDONLY))
    native.info = lambda kind, path: info[kind, Path(path).name]
    native.dump = lambda path: (
        [dict(key=list(struct.pack("=Q", 123)), value=list(struct.pack("=I", 1)))]
        if Path(path).name == "targets" else []
    )
    with patch("agentsuite_guardd.native_network.validate_cgroup_fd",
               return_value=SimpleNamespace(cgroup_id=123)):
        yield native, tmp_path, link


@pytest.mark.parametrize("removed", [False, True])
@pytest.mark.parametrize("change", ["none", "zero", "other-id", "wrong-type", "wrong-hook", "boolean"])
def test_readback_distinguishes_removed_link_from_integrity_failures(cgroup_readback, removed, change):
    native, directory, link = cgroup_readback
    if change == "zero":
        link["cgroup_id"] = 0
    elif change == "other-id":
        link["cgroup_id"] = 999
    elif change == "wrong-type":
        link.update(cgroup_id=0, type="tracing")
    elif change == "wrong-hook":
        link.update(cgroup_id=0, attach_type="cgroup_inet_egress")
    elif change == "boolean":
        link["cgroup_id"] = False
    with patch("agentsuite_guardd.native_network.cgroup_removed", return_value=removed, create=True):
        if change == "none":
            assert native.verify(directory, 99, [])["links"]["connect4"]["cgroup_id"] == 123
        elif change == "zero" and removed:
            with pytest.raises(TargetNotLive):
                native.verify(directory, 99, [])
        else:
            with pytest.raises(ValueError) as error:
                native.verify(directory, 99, [])
            assert not isinstance(error.value, TargetNotLive)
