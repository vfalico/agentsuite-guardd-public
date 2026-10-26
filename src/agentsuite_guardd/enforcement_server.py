"""Node-local mTLS server; the daemon never executes or stops workloads."""
from concurrent.futures import ThreadPoolExecutor
import logging
import os
from pathlib import Path
import signal
import stat
import threading
from urllib.parse import quote

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from orka_enforcement.v1 import enforcement_pb2_grpc as rpc

from .config import load_root_json
from .enforcement_protocol import MAX_RPC_BYTES
from .kubernetes_provider import KubernetesEnforcementProvider
from .kubernetes_api import KubernetesAPI
from .kubernetes_target import KubernetesTargetResolver
from .native_filesystem import FilesystemNative
from .native_container import ContainerNative
from .neutral_service import Service, exact


def node_uid(node_name):
    node = KubernetesAPI().request(
        "GET", "/api/v1/nodes/" + quote(node_name, safe=""), maximum=MAX_RPC_BYTES,
    )
    if node is None:
        raise ValueError("provider Node no longer exists")
    metadata = node["metadata"]
    if metadata["name"] != node_name or not metadata["uid"]:
        raise ValueError("Kubernetes API did not verify this node identity")
    return metadata["uid"]


def private_key(path):
    # Projected Kubernetes Secret symlinks are acceptable; validate the opened
    # inode rather than racing a separate pathname stat.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if metadata.st_uid != 0 or metadata.st_mode & 0o077 or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("root-only regular TLS private key required")
        value = stream.read(65537)
    if not value or len(value) > 65536:
        raise ValueError("TLS private key exceeds credential bound")
    return value


def certificate_bytes(path):
    with open(path, "rb") as stream:
        value = stream.read(65537)
    if not value or len(value) > 65536:
        raise ValueError("TLS certificate exceeds credential bound")
    return value


def server_credentials(config):
    authority = certificate_bytes(config["clientCA"])

    def identity():
        key = private_key(config["privateKey"])
        certificate = certificate_bytes(config["certificate"])
        private = serialization.load_pem_private_key(key, password=None)
        public = x509.load_pem_x509_certificate(certificate).public_key()
        arguments = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if private.public_key().public_bytes(*arguments) != public.public_bytes(*arguments):
            raise ValueError("TLS certificate and private key do not match")
        return key, certificate

    initial = grpc.ssl_server_certificate_configuration(
        [identity()], root_certificates=authority,
    )

    def refresh():
        try:
            if certificate_bytes(config["clientCA"]) != authority:
                raise ValueError("client CA replacement requires explicit trust migration")
            return grpc.ssl_server_certificate_configuration(
                [identity()], root_certificates=authority,
            )
        except (OSError, ValueError, TypeError) as error:
            logging.getLogger(__name__).warning(
                "TLS renewal refused; retaining the previous authenticated identity: %s", error,
            )
            return None

    return grpc.dynamic_ssl_server_credentials(
        initial, refresh, require_client_authentication=True,
    )


def serve_file(path):
    config = load_root_json(path, allow_projected=True)
    keys = {
        "listen", "state", "pins", "filesystemObject", "nodeName", "nodeUID",
        "criCommand", "tls", "allowedClientIdentities",
    }
    exact(config, keys | ({"containerObject"} if "containerObject" in config else set()))
    exact(config["tls"], {"certificate", "privateKey", "clientCA"})
    for key in ("state", "pins", "filesystemObject"):
        if type(config[key]) is not str or not Path(config[key]).is_absolute():
            raise ValueError("absolute trusted provider path required: " + key)
    if "containerObject" in config and (
            type(config["containerObject"]) is not str
            or not Path(config["containerObject"]).is_absolute()):
        raise ValueError("absolute trusted containerObject path required")
    if (type(config["listen"]) is not str or not config["listen"]
            or type(config["allowedClientIdentities"]) is not list
            or not config["allowedClientIdentities"]
            or any(type(item) is not str or not item for item in config["allowedClientIdentities"])):
        raise ValueError("listen address and explicit controller certificate identities required")
    for value in config["tls"].values():
        if type(value) is not str or not Path(value).is_absolute():
            raise ValueError("absolute trusted TLS credential paths required")
    if type(config["nodeName"]) is not str or type(config["nodeUID"]) is not str:
        raise ValueError("node name and optional expected UID must be strings")
    name = config["nodeName"] or os.environ["GUARDD_NODE_NAME"]
    uid = node_uid(name)
    if config["nodeUID"] and config["nodeUID"] != uid:
        raise ValueError("provider placement does not match its registered node UID")
    resolver = KubernetesTargetResolver(name, uid, config["criCommand"])
    credentials = server_credentials(config["tls"])
    backend = FilesystemNative(config["filesystemObject"])
    container = ContainerNative(config["containerObject"]) if "containerObject" in config else None
    service = Service(config["state"], config["pins"], None, backend, container)
    provider = None
    try:
        provider = KubernetesEnforcementProvider(service, resolver, config["allowedClientIdentities"])
        with ThreadPoolExecutor(max_workers=4) as executor:
            server = grpc.server(executor, maximum_concurrent_rpcs=16, options=[
                ("grpc.max_send_message_length", MAX_RPC_BYTES),
                ("grpc.max_receive_message_length", MAX_RPC_BYTES),
            ])
            rpc.add_EnforcementProviderServicer_to_server(provider, server)
            if not server.add_secure_port(config["listen"], credentials):
                raise ValueError("could not bind authenticated provider listener")
            stopping = threading.Event()
            previous = {}
            try:
                for signum in (signal.SIGTERM, signal.SIGINT):
                    previous[signum] = signal.signal(signum, lambda _signum, _frame: stopping.set())
                server.start()
                stopping.wait()
            finally:
                server.stop(5).wait()
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
        # The executor joins every handler before its durable store is closed.
    finally:
        if provider is not None:
            provider.close()
        service.close()
