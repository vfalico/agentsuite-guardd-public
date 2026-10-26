"""Real authenticated gRPC; recording backend, not native enforcement evidence."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import grpc
import pytest

from orka_enforcement.v1 import enforcement_pb2_grpc as rpc
from test_kubernetes_provider import provider_context


def identity(ca_key, ca, name, alternative, usage):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca.subject if ca is not None else x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca is None, path_length=0 if ca is None else None), critical=True)
    )
    if alternative is not None:
        certificate = certificate.add_extension(x509.SubjectAlternativeName([alternative]), critical=False)
    if usage is not None:
        certificate = certificate.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    certificate = certificate.sign(ca_key if ca is not None else key, hashes.SHA256())
    return key, certificate


def key_bytes(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def cert_bytes(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


@contextmanager
def authenticated_channel(provider, principal):
    root_key, root = identity(None, None, "test-ca", None, None)
    server_key, server_cert = identity(
        root_key, root, "provider", x509.DNSName("provider.test"), ExtendedKeyUsageOID.SERVER_AUTH,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        server = grpc.server(executor)
        rpc.add_EnforcementProviderServicer_to_server(provider, server)
        port = server.add_secure_port("127.0.0.1:0", grpc.ssl_server_credentials(
            [(key_bytes(server_key), cert_bytes(server_cert))],
            root_certificates=cert_bytes(root), require_client_auth=True,
        ))
        assert port
        if principal is None:
            credentials = grpc.ssl_channel_credentials(root_certificates=cert_bytes(root))
        else:
            client_key, client_cert = identity(
                root_key, root, "caller", x509.UniformResourceIdentifier(principal),
                ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            credentials = grpc.ssl_channel_credentials(
                root_certificates=cert_bytes(root),
                private_key=key_bytes(client_key), certificate_chain=cert_bytes(client_cert),
            )
        server.start()
        try:
            with grpc.secure_channel(
                f"127.0.0.1:{port}", credentials,
                options=[("grpc.ssl_target_name_override", "provider.test")],
            ) as channel:
                yield rpc.EnforcementProviderStub(channel)
        finally:
            server.stop(5).wait()


def test_authorized_controller_gets_current_bound_evidence(provider_context):
    provider, request, backend, _ = provider_context
    with authenticated_channel(provider, "spiffe://orka.ai/controller") as client:
        proof = client.EnsureEnforced(request, timeout=10)
        assert proof.enforced.binding_id == request.binding_id
        assert proof.enforced.enforced_capabilities == request.requirement.required_capabilities
        assert proof.enforced.evidence
    assert len(backend.installs) == 1


@pytest.mark.parametrize("principal", [None, "spiffe://orka.ai/workload"])
def test_absent_or_wrong_client_identity_cannot_activate(provider_context, principal):
    provider, request, backend, _ = provider_context
    with authenticated_channel(provider, principal) as client:
        with pytest.raises(grpc.RpcError) as failure:
            client.EnsureEnforced(request, timeout=10)
    if principal is None:
        assert failure.value.code() in {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.UNAUTHENTICATED}
    else:
        assert failure.value.code() == grpc.StatusCode.PERMISSION_DENIED
    assert not backend.installs


def test_unicode_refusal_respects_wire_byte_bound(provider_context):
    provider, request, backend, _ = provider_context
    with patch.object(provider, "ensure", side_effect=ValueError("  " + "\u00e9" * 5000 + "  ")):
        with authenticated_channel(provider, "spiffe://orka.ai/controller") as client:
            result = client.EnsureEnforced(request, timeout=10)
    assert result.HasField("refused")
    assert result.refused.reason == "\u00e9" * 2048
    assert len(result.refused.reason.encode("utf-8")) == 4096
    assert not backend.installs
