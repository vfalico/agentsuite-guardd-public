"""Kernel ID absence discriminator; no bpftool text or JSON interpretation."""
import ctypes as C
import errno
import os
from unittest.mock import patch

import pytest
from agentsuite_guardd.native_network import Native


class Lookup:
    def __init__(self, result, error=0):
        self.result, self.error = result, error
        self.calls = []

    def __call__(self, object_id):
        self.calls.append(object_id)
        C.set_errno(self.error)
        return self.result


def backend(result, error=0):
    native = Native.__new__(Native)
    native.lib = type("Library", (), {})()
    call = Lookup(result, error)
    for kind in ("map", "prog", "link"):
        setattr(native.lib, "bpf_" + kind + "_get_fd_by_id", call)
    return native, call


@pytest.mark.parametrize("kind", ["map", "prog", "link"])
def test_enoent_only_proves_absence(kind):
    native, lookup = backend(-1, errno.ENOENT)
    assert native.object_exists(kind, 123) is False
    assert lookup.calls == [123]


@pytest.mark.parametrize("error", [errno.EPERM, errno.EACCES, errno.EINVAL, errno.EINTR, errno.EIO])
def test_other_kernel_errors_remain_uncertain(error):
    native, lookup = backend(-1, error)
    with pytest.raises(OSError) as failure:
        native.object_exists("map", 123)
    assert failure.value.errno == error


def test_success_closes_owned_fd_even_fd_zero():
    native, lookup = backend(0)
    with patch.object(os, "close") as close:
        assert native.object_exists("link", 123) is True
        close.assert_called_once_with(0)


@pytest.mark.parametrize("value", [0, -1, 2**32, True, "123"])
def test_invalid_id_never_calls_kernel(value):
    native, lookup = backend(-1, errno.ENOENT)
    with pytest.raises(ValueError):
        native.object_exists("map", value)
    assert not lookup.calls


def test_invalid_kind_never_looks_up():
    native, lookup = backend(-1, errno.ENOENT)
    with pytest.raises(ValueError):
        native.object_exists("unknown", 123)
    assert not lookup.calls
