"""Real Unix sockets; no native enforcement claim."""
import os
import socket
from pathlib import Path
import pytest
from agentsuite_guardd.neutral_service import bind_owned_socket

@pytest.fixture
def address(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("root socket ownership qualification")
    return str(tmp_path / "service.sock")

def test_dead_owned_socket_recovered(address):
    old=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    old.bind(address);os.chmod(address,0o600);old.close()
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as new:
        bound=bind_owned_socket(new,address)
        assert Path(address).lstat().st_ino==bound.st_ino

def test_live_socket_never_replaced(address):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as live:
        live.bind(address);os.chmod(address,0o600);live.listen(2)
        inode=Path(address).lstat().st_ino
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as new:
            with pytest.raises(ValueError,match="live socket"):
                bind_owned_socket(new,address)
        assert Path(address).lstat().st_ino==inode

@pytest.mark.parametrize("kind",["file","symlink","wide-socket","wide-parent"])
def test_untrusted_address_refused(address,kind):
    path=Path(address)
    if kind=="file":path.write_text("foreign")
    elif kind=="symlink":path.symlink_to(path.parent/"other")
    elif kind=="wide-parent":path.parent.chmod(0o777)
    else:
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as stale:stale.bind(address)
        path.chmod(0o666)
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as new:
        with pytest.raises(ValueError):bind_owned_socket(new,address)
    if kind=="wide-parent":path.parent.chmod(0o700)
