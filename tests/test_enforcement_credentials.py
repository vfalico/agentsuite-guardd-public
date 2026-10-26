"""Leaf renewal on one live authenticated listener, without backend restart."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import logging
import os
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
import grpc
import pytest

from agentsuite_guardd.enforcement_server import server_credentials
from test_enforcement_mtls import cert_bytes, identity, key_bytes


pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="root-owned projected TLS key contract")


def publish(directory, name, key, certificate, authority):
    generation = directory / name
    generation.mkdir()
    for filename, value in (
        ("server.key", key_bytes(key)),
        ("server.crt", cert_bytes(certificate)),
        ("client-ca.crt", cert_bytes(authority)),
    ):
        path = generation / filename
        path.write_bytes(value)
        path.chmod(0o600)
    temporary = directory / "next"
    temporary.symlink_to(name)
    temporary.replace(directory / "..data")


@contextmanager
def listener(directory):
    root_key, root = identity(None, None, "test-ca", None, None)
    key, certificate = identity(
        root_key, root, "provider", x509.DNSName("provider.test"), ExtendedKeyUsageOID.SERVER_AUTH,
    )
    publish(directory, "initial", key, certificate, root)
    for filename in ("server.key", "server.crt", "client-ca.crt"):
        (directory / filename).symlink_to("..data/" + filename)
    config = {
        "privateKey": str(directory / "server.key"),
        "certificate": str(directory / "server.crt"),
        "clientCA": str(directory / "client-ca.crt"),
    }
    client_key, client_cert = identity(
        root_key, root, "caller", x509.UniformResourceIdentifier("spiffe://controller.test"),
        ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    client_key_path, client_cert_path = directory / "client.key", directory / "client.crt"
    client_key_path.write_bytes(key_bytes(client_key))
    client_cert_path.write_bytes(cert_bytes(client_cert))
    context = ssl.create_default_context(cadata=cert_bytes(root).decode("ascii"))
    context.set_alpn_protocols(["h2"])
    context.load_cert_chain(client_cert_path, client_key_path)
    with ThreadPoolExecutor(max_workers=1) as executor:
        server = grpc.server(executor)
        server.add_generic_rpc_handlers([grpc.method_handlers_generic_handler(
            "credentials", {"check": grpc.unary_unary_rpc_method_handler(lambda _request, _context: b"ok")},
        )])
        port = server.add_secure_port("127.0.0.1:0", server_credentials(config))
        assert port
        server.start()

        def peer_serial():
            with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                with context.wrap_socket(connection, server_hostname="provider.test") as secured:
                    return x509.load_der_x509_certificate(secured.getpeercert(binary_form=True)).serial_number

        def request(alternate=None):
            private, certificate = alternate if alternate is not None else (client_key, client_cert)
            credentials = grpc.ssl_channel_credentials(
                root_certificates=cert_bytes(root),
                private_key=key_bytes(private) if private is not None else None,
                certificate_chain=cert_bytes(certificate) if certificate is not None else None,
            )
            with grpc.secure_channel(
                f"127.0.0.1:{port}", credentials,
                options=[("grpc.ssl_target_name_override", "provider.test"),
                         ("grpc.use_local_subchannel_pool", 1)],
            ) as channel:
                return channel.unary_unary("/credentials/check")(b"", timeout=5)

        try:
            yield root_key, root, key, certificate, peer_serial, request
        finally:
            server.stop(5).wait()


def test_projected_leaf_renewal_changes_the_live_certificate(tmp_path):
    with listener(tmp_path) as (root_key, root, _key, certificate, peer_serial, request):
        assert peer_serial() == certificate.serial_number
        assert request() == b"ok"
        next_key, next_cert = identity(
            root_key, root, "provider", x509.DNSName("provider.test"), ExtendedKeyUsageOID.SERVER_AUTH,
        )
        publish(tmp_path, "renewed", next_key, next_cert, root)
        assert peer_serial() == next_cert.serial_number
        assert request() == b"ok"


@pytest.mark.parametrize("invalid", ["mismatched-key", "public-key-file", "replaced-client-ca"])
def test_bad_renewal_keeps_current_authenticated_listener(tmp_path, caplog, invalid):
    with listener(tmp_path) as (root_key, root, key, certificate, peer_serial, request):
        assert request() == b"ok"
        next_key, next_cert = identity(
            root_key, root, "provider", x509.DNSName("provider.test"), ExtendedKeyUsageOID.SERVER_AUTH,
        )
        authority = root
        if invalid == "mismatched-key":
            next_key = key
        elif invalid == "replaced-client-ca":
            _, authority = identity(None, None, "other-ca", None, None)
        publish(tmp_path, "invalid", next_key, next_cert, authority)
        if invalid == "public-key-file":
            (tmp_path / "invalid/server.key").chmod(0o644)
        assert peer_serial() == certificate.serial_number
        assert request() == b"ok"
        assert any(
            record.name == "agentsuite_guardd.enforcement_server" and record.levelno >= logging.WARNING
            for record in caplog.records
        )


@pytest.mark.parametrize("untrusted", ["missing", "other-issuer"])
def test_new_connections_require_client_authentication_after_renewal(tmp_path, untrusted):
    with listener(tmp_path) as (root_key, root, _key, _certificate, _peer_serial, request):
        alternate = (None, None)
        if untrusted == "other-issuer":
            other_key, other_root = identity(None, None, "other-ca", None, None)
            alternate = identity(
                other_key, other_root, "caller", x509.UniformResourceIdentifier("spiffe://controller.test"),
                ExtendedKeyUsageOID.CLIENT_AUTH,
            )
        for generation in ("initial", "renewed"):
            if generation == "renewed":
                next_key, next_cert = identity(
                    root_key, root, "provider", x509.DNSName("provider.test"), ExtendedKeyUsageOID.SERVER_AUTH,
                )
                publish(tmp_path, generation, next_key, next_cert, root)
            assert request() == b"ok"
            with pytest.raises(grpc.RpcError) as failure:
                request(alternate)
            assert failure.value.code() in {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.UNAUTHENTICATED}
