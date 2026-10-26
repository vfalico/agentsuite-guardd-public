"""Trusted containerd/CRI resolution for the qualified Kubernetes profile."""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import subprocess

from .neutral_service import canonical, exact, target_identity
from .target import validate_cgroup_fd, TargetNotLive

FACTS_FORMAT = "orka.kubernetes-container/v1"
PHYSICAL_FORMAT = "agentsuite.linux-container/v1"
FACT_FIELDS = {
    "nodeName", "nodeUID", "namespace", "podName", "podUID",
    "containerName", "containerID",
}
FORBIDDEN_CAPABILITIES = {
    "CAP_SYS_ADMIN", "CAP_BPF", "CAP_PERFMON", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
}
MAX_CRI_BYTES = 4 << 20


class TargetPending(Exception):
    """The exact incarnation is not live; the runtime must reconcile its lifecycle."""


def parse_facts(facts, node_name, node_uid):
    if facts.format != FACTS_FORMAT:
        raise ValueError("qualified target facts format required: " + FACTS_FORMAT)
    value = json.loads(facts.value)
    exact(value, FACT_FIELDS)
    if canonical(value) != facts.value:
        raise ValueError("Kubernetes target facts require canonical JSON")
    if any(type(item) is not str or not item or len(item) > 512
           or not item.isascii() or "\0" in item for item in value.values()):
        raise ValueError("invalid Kubernetes container identity")
    if value["nodeName"] != node_name or value["nodeUID"] != node_uid:
        raise ValueError("target does not belong to this authenticated node incarnation")
    if not re.fullmatch(r"containerd://[a-f0-9]{64}", value["containerID"]):
        raise ValueError("qualified containerd target requires a full immutable container ID")
    return value


def validate_inspection(facts, inspection):
    status = inspection["status"]
    container_id = facts["containerID"].removeprefix("containerd://")
    if status["id"] != container_id or status["metadata"]["name"] != facts["containerName"]:
        raise ValueError("CRI container incarnation/name mismatch")
    expected = {
        "io.kubernetes.pod.uid": facts["podUID"],
        "io.kubernetes.pod.name": facts["podName"],
        "io.kubernetes.pod.namespace": facts["namespace"],
        "io.kubernetes.container.name": facts["containerName"],
    }
    if any(status.get("labels", {}).get(key) != value for key, value in expected.items()):
        raise ValueError("CRI Kubernetes ownership mismatch")
    if status["state"] == "CONTAINER_CREATED":
        raise TargetPending("container bootstrap is not running yet")
    if status["state"] == "CONTAINER_EXITED":
        raise TargetPending("container exited; runtime must reconcile and retire this incarnation")
    if status["state"] != "CONTAINER_RUNNING":
        raise ValueError("target container is not running")
    info = inspection["info"]
    pid = info["pid"]
    if type(pid) is not int or pid <= 1:
        raise ValueError("CRI did not resolve a live host PID")
    spec = info["runtimeSpec"]
    namespaces = spec["linux"]["namespaces"]
    for kind in ("pid", "mount"):
        matches = [item for item in namespaces if item.get("type") == kind]
        if len(matches) != 1 or matches[0].get("path"):
            raise ValueError("qualified profile requires private PID and mount namespaces")
    capabilities = spec["process"].get("capabilities", {})
    if type(capabilities) is not dict or any(
        type(group) is not list or any(type(item) is not str for item in group)
        for group in capabilities.values()
    ):
        raise ValueError("invalid OCI capability inventory")
    if any(FORBIDDEN_CAPABILITIES.intersection(group) for group in capabilities.values()):
        raise ValueError("container privileges can escape the qualified enforcement boundary")
    mounts = [item for item in spec["mounts"] if item.get("destination") == "/sys/fs/cgroup"]
    if len(mounts) != 1 or "ro" not in mounts[0].get("options", []):
        raise ValueError("qualified profile requires read-only container cgroup access")
    return pid


def validate_cgroup_mounts(mountinfo):
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        filesystem = after.split()
        if not separator or len(fields) < 6 or not filesystem:
            raise ValueError("incomplete target mount inventory")
        if filesystem[0] in {"cgroup", "cgroup2"}:
            options = fields[5].split(",")
            if "ro" not in options or "rw" in options:
                raise ValueError("every exposed cgroupfs mount, including aliases, must be read-only")


@contextmanager
def live_process(pidfd):
    """Translate only typed target loss confirmed by the exact held process."""
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    message = "container exited during enforcement; runtime must reconcile and retire this incarnation"

    def exited():
        events = poller.poll(0)
        if any(mask & (select.POLLERR | select.POLLNVAL) for _, mask in events):
            raise RuntimeError("resolved container lifetime is uncertain")
        return any(mask & (select.POLLIN | select.POLLHUP) for _, mask in events)

    if exited():
        raise TargetPending(message)
    try:
        yield
    except TargetNotLive as error:
        if exited():
            raise TargetPending(message) from error
        raise
    if exited():
        raise TargetPending(message)


@dataclass(frozen=True)
class ResolvedContainer:
    facts: dict
    target: dict
    cgroup_path: str
    fds: tuple

    def physical(self):
        return dict(
            container=self.facts, kernel=self.target, cgroupPath=self.cgroup_path,
        )

    def live(self):
        """Observe exact root-process lifetime, never whole-cgroup cleanup authority."""
        return live_process(self.fds[1])


class KubernetesTargetResolver:
    def __init__(self, node_name, node_uid, cri_command, cgroup_root="/sys/fs/cgroup"):
        if not node_name or not node_uid:
            raise ValueError("operator-bound node name and UID are required")
        if (not cri_command or any(type(item) is not str or not item for item in cri_command)
                or not Path(cri_command[0]).is_absolute()):
            raise ValueError("absolute operator-configured CRI command required")
        self.node_name, self.node_uid = node_name, node_uid
        self.cri_command = tuple(cri_command)
        self.cgroup_root = Path(cgroup_root)

    def facts(self, value):
        return parse_facts(value, self.node_name, self.node_uid)

    def cri(self, *arguments):
        result = subprocess.run(
            [*self.cri_command, *arguments], capture_output=True, timeout=10, check=False,
        )
        if result.returncode != 0:
            # Runtime errors may include process configuration. Never echo them.
            raise RuntimeError("CRI request failed; physical container state is uncertain")
        if len(result.stdout) > MAX_CRI_BYTES:
            raise RuntimeError("CRI response exceeds the qualified metadata bound")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("CRI returned invalid container metadata") from error

    @contextmanager
    def resolve(self, value):
        facts = self.facts(value)
        container_id = facts["containerID"].removeprefix("containerd://")
        inspection = self.cri("inspect", "--output", "json", container_id)
        try:
            pid = validate_inspection(facts, inspection)
        except (KeyError, TypeError) as error:
            raise ValueError("incomplete qualified containerd metadata") from error
        with ExitStack() as stack:
            def hold(fd):
                stack.callback(os.close, fd)
                return fd

            root = hold(os.open(self.cgroup_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
            root_identity = validate_cgroup_fd(root)
            mounts = [
                line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
                if line.split()[0] == str(root_identity.mount_id)
            ]
            if (len(mounts) != 1 or mounts[0][3] != "/"
                    or os.readlink("/proc/self/ns/cgroup") != os.readlink("/proc/1/ns/cgroup")):
                raise ValueError("provider requires the host cgroup namespace and complete hierarchy mount")
            if pid == os.getpid():
                raise ValueError("provider must run outside the governed container")
            pidfd = hold(os.pidfd_open(pid))
            with live_process(pidfd):
                entries = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
                if len(entries) != 1 or not entries[0].startswith("0::/"):
                    raise ValueError("qualified profile requires a unified host cgroup view")
                cgroup_path = entries[0][3:]
                parts = PurePosixPath(cgroup_path).parts[1:]
                if (not parts or len(parts) >= 64 or any(item in {".", ".."} for item in parts)
                        or PurePosixPath(cgroup_path).as_posix() != cgroup_path
                        or parts[-1] not in {container_id, "cri-containerd-" + container_id + ".scope"}):
                    raise ValueError("container cgroup is outside the qualified identity/depth profile")
                cgroupfd = hold(os.open(
                    "/".join(parts), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=root,
                ))
                netns = hold(os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC))
                start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                target = dict(
                    target_identity(cgroupfd), pid=pid, start=start,
                    netns=os.fstat(netns).st_ino, generation=1,
                )
                validate_cgroup_mounts(Path(f"/proc/{pid}/mountinfo").read_text())
                yield ResolvedContainer(facts, target, cgroup_path, (cgroupfd, pidfd, netns))

    def stopped(self, facts):
        container_id = facts["containerID"].removeprefix("containerd://")
        result = self.cri("ps", "--all", "--id", container_id, "--output", "json")
        containers = result.get("containers")
        if type(containers) is not list:
            raise RuntimeError("CRI did not return a complete container inventory")
        for container in containers:
            if type(container) is not dict or type(container.get("id")) is not str:
                raise RuntimeError("CRI returned an invalid container inventory")
            if container["id"] == container_id:
                return container.get("state") == "CONTAINER_EXITED", result
        # A successful exact-ID ListContainers absence is runtime proof.
        # A failed inspect/RPC is deliberately never used as absence.
        return True, result
