from __future__ import annotations
from dataclasses import dataclass
from base64 import b64decode
import json, os, stat


def load_root_json(path: str, maximum: int = 16384, *, allow_projected: bool = False) -> dict:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if not allow_projected:
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    with os.fdopen(fd) as stream:
        metadata = os.fstat(stream.fileno())
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("root-owned non-writable regular configuration required")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("configuration too large")
    value = json.loads(raw)
    if type(value) is not dict:
        raise ValueError("configuration must be a JSON object")
    return value


@dataclass(frozen=True)
class Config:
    listen: str
    state: str
    key_file: str
    backend_state: str
    adapter_state: str
    bpffs_root: str
    cgroup_root: str
    bpftool: str
    backend: str = "persistent"
    provider_id: str = "agentsuite-guardd/v1"
    endpoint_id: str = "local-unix"
    socket_mode: int = 0o660
    allowed_uids: tuple[int, ...] = (0,)


def load_config(path: str) -> Config:
    with open(path, encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError("configuration must be a JSON object")
    required = {
        "listen",
        "state",
        "keyFile",
        "backendState",
        "adapterState",
        "bpffsRoot",
        "cgroupRoot",
        "bpftool",
        "providerId",
        "endpointId",
    }
    missing = required - set(value)
    if missing:
        raise ValueError("missing configuration fields: " + ", ".join(sorted(missing)))
    for field in required:
        if not isinstance(value[field], str) or not value[field]:
            raise ValueError(f"{field} must be a nonempty string")
    if value["providerId"] != "agentsuite-guardd/v1":
        raise ValueError("provider identity mismatch")
    listen = value["listen"]
    if (
        not isinstance(listen, str)
        or not listen.startswith("unix://")
        or not listen[7:].startswith("/")
    ):
        raise ValueError("listen must be an absolute unix:// URL")
    mode = value.get("socketMode", "0660")
    if not isinstance(mode, (str, int)) or isinstance(mode, bool):
        raise ValueError("socketMode must be an octal string or integer")
    socket_mode = int(mode, 8) if isinstance(mode, str) else mode
    if not 0 <= socket_mode <= 0o777:
        raise ValueError("socketMode must contain only permission bits")
    raw_uids = value.get("allowedUIDs", [0])
    if not isinstance(raw_uids, list):
        raise ValueError("allowedUIDs must be a list")
    if any(type(uid) is not int or uid < 0 for uid in raw_uids):
        raise ValueError("allowedUIDs entries must be nonnegative integers")
    uids = tuple(raw_uids)
    if not uids:
        raise ValueError("allowedUIDs must not be empty")
    backend = value.get("backend", "persistent")
    if not isinstance(backend, str) or not backend:
        raise ValueError("backend must be a nonempty string")
    return Config(
        listen,
        value["state"],
        value["keyFile"],
        value["backendState"],
        value["adapterState"],
        value["bpffsRoot"],
        value["cgroupRoot"],
        value["bpftool"],
        backend,
        value["providerId"],
        value["endpointId"],
        socket_mode,
        uids,
    )


def load_signing_seed(path: str) -> bytes:
    st = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("signing credential must be a regular file")
    if st.st_uid != 0:
        raise PermissionError("signing credential must be owned by root")
    if st.st_mode & 0o077:
        raise PermissionError("signing credential must not be group/world accessible")
    raw = PathLike.read(path)
    if len(raw) == 32:
        return raw
    try:
        decoded = b64decode(raw.strip(), validate=True)
    except ValueError as e:
        raise ValueError("signing credential must be 32 raw bytes or base64") from e
    if len(decoded) != 32:
        raise ValueError("signing credential must decode to exactly 32 bytes")
    return decoded


class PathLike:
    @staticmethod
    def read(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()
