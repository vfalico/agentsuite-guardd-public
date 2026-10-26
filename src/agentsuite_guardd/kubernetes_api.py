"""Bounded Kubernetes requests using the current projected service account."""
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


class Conflict(ValueError):
    pass


class KubernetesAPI:
    def __init__(self):
        self.directory = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        if ":" in host:
            host = "[" + host + "]"
        port = int(os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443"))
        if not 0 < port < 65536:
            raise ValueError("invalid Kubernetes API port")
        self.origin = f"https://{host}:{port}"
        context = ssl.create_default_context(cafile=self.directory / "ca.crt")
        self.transport = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())

    def request(self, method, path, body=None, *, content_type="application/json", maximum=8 << 20):
        if not path.startswith("/") or path.startswith("//") or "#" in path:
            raise ValueError("Kubernetes resource path must stay on the pinned API origin")
        with (self.directory / "token").open("rb") as stream:
            token = stream.read(65537)
        if len(token) > 65536 or not token.strip():
            raise ValueError("invalid projected Kubernetes service account token")
        token = token.decode("ascii").strip()
        request = Request(
            self.origin + path,
            data=json.dumps(body, separators=(",", ":")).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + token, "Content-Type": content_type},
            method=method,
        )
        try:
            with self.transport.open(request, timeout=10) as response:
                raw = response.read(maximum + 1)
        except HTTPError as error:
            if method == "GET" and error.code == 404:
                return None
            if error.code == 409:
                raise Conflict("Kubernetes resource changed concurrently: " + path) from None
            raise ValueError(f"Kubernetes {method} refused (HTTP {error.code}): {path}") from None
        if len(raw) > maximum:
            raise ValueError("Kubernetes response exceeds metadata bound")
        value = json.loads(raw)
        if type(value) is not dict:
            raise ValueError("Kubernetes response must be an object")
        return value
