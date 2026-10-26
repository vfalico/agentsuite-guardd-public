"""Bounded metadata transport and the root-owned projected configuration lane."""
import io
import json
import os
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from agentsuite_guardd.config import load_root_json
from agentsuite_guardd.kubernetes_api import Conflict, KubernetesAPI, NoRedirect


def client(tmp_path):
    api = KubernetesAPI.__new__(KubernetesAPI)
    api.directory = tmp_path
    api.origin = "https://cluster.invalid:443"
    (tmp_path / "token").write_text("original-token")
    return api


def test_current_projected_token_and_response_bound(tmp_path):
    api = client(tmp_path)
    observed = []

    class Transport:
        def open(self, request, timeout):
            observed.append(request.get_header("Authorization"))
            return io.BytesIO(b'{"metadata":{"uid":"node"}}')

    api.transport = Transport()
    assert api.request("GET", "/api/v1/nodes/worker")["metadata"]["uid"] == "node"
    (tmp_path / "token").write_text("rotated-token")
    api.request("GET", "/api/v1/nodes/worker")
    assert observed == ["Bearer original-token", "Bearer rotated-token"]
    with pytest.raises(ValueError):
        api.request("GET", "/api/v1/nodes/worker", maximum=5)


@pytest.mark.parametrize("status", [302, 401, 404, 409, 500])
def test_api_errors_do_not_leak_response_credentials(tmp_path, status):
    api = client(tmp_path)

    class Transport:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, status, "private server error", {}, io.BytesIO(b"private-body"))

    api.transport = Transport()
    if status == 404:
        assert api.request("GET", "/api/v1/nodes/worker") is None
    else:
        with pytest.raises(Conflict if status == 409 else ValueError) as failure:
            api.request("GET", "/api/v1/nodes/worker")
        assert "private" not in str(failure.value)
        assert "original-token" not in str(failure.value)


def test_redirect_handler_never_constructs_credential_bearing_redirect():
    request = Request("https://cluster.invalid/api", headers={"Authorization": "Bearer private"})
    for destination in ("https://other.invalid/api", "http://cluster.invalid/api", "/moved"):
        assert NoRedirect().redirect_request(request, None, 302, "moved", {}, destination) is None


def test_projected_configuration_requires_explicit_lane_and_safe_opened_inode(tmp_path):
    if os.getuid() != 0:
        pytest.skip("actual root-owned inode validation requires root")
    target = tmp_path / "config.json"
    target.write_text(json.dumps({"nodeName": "worker"}))
    target.chmod(0o400)
    link = tmp_path / "projected.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        load_root_json(link)
    assert load_root_json(link, allow_projected=True) == {"nodeName": "worker"}
    target.chmod(0o666)
    with pytest.raises(ValueError):
        load_root_json(link, allow_projected=True)
    target.chmod(0o400)
    with pytest.raises(ValueError):
        load_root_json(link, maximum=2, allow_projected=True)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError):
        load_root_json(fifo, allow_projected=True)


