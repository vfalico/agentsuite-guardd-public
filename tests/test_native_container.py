"""Opt-in native qualification; run as root with GUARDD_FILESYSTEM_OBJECT set."""
import base64
import errno
import json
import logging
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import uuid

import pytest

from agentsuite_guardd.model import canonical, policy_digest
from agentsuite_guardd.native_filesystem import FilesystemNative
from agentsuite_guardd.neutral_service import Service, target_identity
from agentsuite_guardd.target import task_ids


WORKER = """
import json, os, pathlib, subprocess, sys
protected, allowed, descendant = sys.argv[1:]
sys.stdin.buffer.read(1)
resident = subprocess.Popen(
    [sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"],
    stdin=subprocess.PIPE,
)
try:
    probe = '''
import errno, json, os, sys
if sys.argv[2]:
    with open(sys.argv[2] + "/cgroup.procs", "w") as stream:
        stream.write(str(os.getpid()))
try:
    with open(sys.argv[1], "w") as stream:
        stream.write("forbidden")
except OSError as error:
    print(json.dumps(error.errno))
else:
    print("0")
'''
    denied = subprocess.check_output(
        [sys.executable, "-c", probe, protected, descendant], timeout=10,
    )
    pathlib.Path(allowed).write_text("allowed")
    print(json.dumps({"errno": json.loads(denied), "resident": resident.pid}), flush=True)
    sys.stdin.buffer.read(1)
finally:
    resident.communicate(input=b"x", timeout=10)
"""


def terminate_members(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for pid in task_ids(fd):
            try:
                handle = os.pidfd_open(pid)
            except ProcessLookupError:
                logging.getLogger(__name__).debug("owned process %s already exited", pid)
                continue
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            finally:
                os.close(handle)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    ("descendant", "deleted"),
    [(False, False), (True, False), (False, True)],
    ids=["container", "child-cgroup", "deleted-cgroup"],
)
def test_real_root_mutations_and_populated_readback(tmp_path, descendant, deleted):
    object_path = os.environ.get("GUARDD_FILESYSTEM_OBJECT")
    if not object_path:
        pytest.skip("set GUARDD_FILESYSTEM_OBJECT for privileged native qualification")
    if os.geteuid() != 0:
        pytest.fail("native qualification requires root")
    object_path = Path(object_path).resolve(strict=True)
    current = next(
        line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    scope = Path("/sys/fs/cgroup") / current.lstrip("/") / ("guardd-test-" + uuid.uuid4().hex)
    scope.mkdir()
    nested = scope / "nested"
    nested.mkdir()
    protected = tmp_path / "repository"
    protected.mkdir()
    canary = protected / "canary"
    canary.write_text("original")
    (protected / "link").symlink_to("canary")
    allowed = tmp_path / "allowed"
    raw = canonical(dict(
        version="agentsuite.policy/v1", denyWritePaths=[str(protected)],
        requiredCapabilities=["filesystem/deny-write/v1"],
    ))
    requirement = dict(
        format="agentsuite.policy/v1", bytes=base64.b64encode(raw).decode(),
        digest=policy_digest(raw), capabilities=["filesystem/deny-write/v1"],
    )
    pins = Path("/sys/fs/bpf") / ("guardd-test-" + uuid.uuid4().hex)
    service = Service(tmp_path / "bindings.db", pins, None, FilesystemNative(object_path))
    process = subprocess.Popen(
        [sys.executable, "-c", WORKER, str(canary), str(allowed),
         str(nested) if descendant else ""],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    fds = []
    request = None
    try:
        (scope / "cgroup.procs").write_text(str(process.pid))
        fds = [
            os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC),
            os.pidfd_open(process.pid),
            os.open(f"/proc/{process.pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC),
        ]
        start = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        target = dict(
            target_identity(fds[0]), pid=process.pid, start=start,
            netns=os.fstat(fds[2]).st_ino, generation=1,
        )
        request = dict(
            version="execution-enforcement/v1", method="activate",
            operation="native-container", requirement=requirement, target=target,
        )
        assert service.dispatch(request, fds)["active"]
        process.stdin.write(b"x")
        process.stdin.flush()
        assert select.select([process.stdout], [], [], 20)[0], "native probe did not report"
        result = json.loads(process.stdout.readline())
        assert result["errno"] == errno.EACCES
        assert canary.read_text() == "original"
        assert allowed.read_text() == "allowed"
        assert result["resident"] in task_ids(fds[0])
        assert service.dispatch(dict(request, method="lookup"), [fds[0]])["active"]
        with pytest.raises(ValueError, match="runtime-stopped"):
            service.dispatch(dict(request, method="retire"), [fds[0]])
        process.communicate(input=b"x", timeout=20)
        assert process.returncode == 0
        if deleted:
            nested.rmdir()
            scope.rmdir()
            with pytest.raises(ValueError, match="unlinked"):
                service.dispatch(dict(request, method="lookup"), [fds[0]])
        assert service.dispatch(dict(request, method="retire"), [fds[0]])["retired"]
        assert not any(pins.iterdir())
    finally:
        if nested.exists():
            terminate_members(nested)
        if scope.exists():
            terminate_members(scope)
        process.communicate(timeout=10)
        try:
            if request is not None:
                service.dispatch(dict(request, method="retire"), [fds[0]])
        finally:
            service.close()
            for fd in reversed(fds):
                os.close(fd)
            if nested.exists():
                nested.rmdir()
            if scope.exists():
                scope.rmdir()
            if not any(pins.iterdir()):
                pins.rmdir()
