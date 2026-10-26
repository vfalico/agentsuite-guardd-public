"""Finite, installation-owned Kubernetes provisioning; never workload admission."""
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import quote

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .kubernetes_api import Conflict, KubernetesAPI
from .neutral_service import exact


PREFIX = "enforcement.guardd.dev/"
MAX_REGISTRY_BYTES = 512 << 10
RESOURCES = {
    "ConfigMap": ("/api/v1", "configmaps"),
    "Secret": ("/api/v1", "secrets"),
    "Service": ("/api/v1", "services"),
    "Deployment": ("/apis/apps/v1", "deployments"),
}


def encoded(value):
    return b64encode(value).decode("ascii")


def pem_key(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def pem_certificate(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def same_key(key, certificate):
    arguments = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    return key.public_key().public_bytes(*arguments) == certificate.public_key().public_bytes(*arguments)


def issue(key, issuer, subject, alternative=None, usage=None):
    now = datetime.now(timezone.utc)
    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    certificate = (
        x509.CertificateBuilder().subject_name(name)
        .issuer_name(issuer.subject if issuer is not None else name)
        .public_key(private.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30 if issuer is not None else 3650))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=0 if issuer is None else None), True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=issuer is None,
            crl_sign=issuer is None, encipher_only=False, decipher_only=False,
        ), True)
    )
    if alternative is not None:
        certificate = certificate.add_extension(x509.SubjectAlternativeName([alternative]), False)
    if usage is not None:
        certificate = certificate.add_extension(x509.ExtendedKeyUsage([usage]), False)
    return private, certificate.sign(key if key is not None else private, hashes.SHA256())


class Installation:
    def __init__(self, api, namespace, name):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", namespace):
            raise ValueError("invalid installation namespace")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?", name):
            raise ValueError("installation name must be a DNS label of at most 39 characters")
        self.api, self.namespace, self.name = api, namespace, name
        self.anchor_path = self.path("ConfigMap", name + "-installation")
        self.anchor = api.request("GET", self.anchor_path)
        if self.anchor is None:
            raise ValueError("installation configuration does not exist")
        self.raw = self.anchor["data"]["config.json"]
        if len(self.raw.encode()) > 16384:
            raise ValueError("installation configuration exceeds bound")
        self.config = json.loads(self.raw)
        exact(self.config, {
            "releaseName", "releaseNamespace", "revision", "isInstall", "enabled",
            "existingInstallationUID", "image", "imagePullPolicy", "criSocketDirectory",
            "criSocketName", "stateDirectory", "controllerIdentity", "controllerMountDirectory",
            "nodeSelector", "imagePullSecrets",
        })
        self.uid = self.anchor["metadata"]["uid"]
        self.state_path = self.path("ConfigMap", name + "-state")
        self.state_uid = None
        self.revision = self.config["revision"]
        self.generation = None
        if (type(self.revision) is not int or self.revision < 1
                or type(self.config["enabled"]) is not bool
                or type(self.config["isInstall"]) is not bool):
            raise ValueError("explicit installation revision and enrollment state required")
        for field in ("releaseName", "releaseNamespace", "existingInstallationUID", "image",
                      "imagePullPolicy", "criSocketName"):
            if type(self.config[field]) is not str:
                raise ValueError("installation string required: " + field)
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,52}", self.config["releaseName"]):
            raise ValueError("invalid Helm release name")
        self._helm_owned(self.anchor)
        for key in ("criSocketDirectory", "stateDirectory", "controllerMountDirectory"):
            value = self.config[key]
            if (type(value) is not str or not value.startswith("/") or value == "/"
                    or ".." in PurePosixPath(value).parts):
                raise ValueError("absolute restricted installation directory required: " + key)
        if not re.fullmatch(r"[A-Za-z0-9._-]+", self.config["criSocketName"]):
            raise ValueError("CRI socket must be one filename")
        if (type(self.config["controllerIdentity"]) is not str
                or not self.config["controllerIdentity"].startswith("spiffe://")):
            raise ValueError("explicit controller certificate URI required")
        selector = self.config["nodeSelector"]
        if (type(selector) is not dict or selector.get("kubernetes.io/os") != "linux"
                or selector.get("kubernetes.io/arch") != "amd64"
                or any(type(k) is not str or type(v) is not str for k, v in selector.items())):
            raise ValueError("initial node selector must select linux/amd64")
        if self.config["enabled"] and not re.fullmatch(
            r"[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}", self.config["image"],
        ):
            raise ValueError("enabled provider image must be digest-pinned")
        if self.config["imagePullPolicy"] not in {"Always", "IfNotPresent", "Never"}:
            raise ValueError("invalid provider image pull policy")
        if (type(self.config["imagePullSecrets"]) is not list
                or any(type(item) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", item)
                       for item in self.config["imagePullSecrets"])):
            raise ValueError("image pull Secrets must be explicit resource names")

    def path(self, kind, name=None):
        group, resource = RESOURCES[kind]
        base = f"{group}/namespaces/{quote(self.namespace, safe='')}/{resource}"
        return base + "/" + quote(name, safe="") if name is not None else base

    def _helm_owned(self, resource):
        metadata = resource["metadata"]
        annotations = metadata.get("annotations", {})
        if (metadata.get("namespace") != self.namespace
                or metadata.get("labels", {}).get("app.kubernetes.io/managed-by") != "Helm"
                or annotations.get("meta.helm.sh/release-name") != self.config["releaseName"]
                or annotations.get("meta.helm.sh/release-namespace") != self.config["releaseNamespace"]
                or self.config["releaseNamespace"] != self.namespace):
            raise ValueError("foreign installation configuration cannot be adopted")

    def _desired(self):
        current = self.api.request("GET", self.anchor_path)
        if (current is None or current["metadata"]["uid"] != self.uid
                or current.get("data", {}).get("config.json") != self.raw):
            raise Conflict("installation configuration changed; refusing stale writer")
        return current

    def _load_state(self):
        self._desired()
        current = self.api.request("GET", self.state_path)
        if current is None:
            for kind, name in (
                ("Secret", self.name + "-authority"),
                ("Secret", self.name + "-controller-identity"),
                ("ConfigMap", self.name + "-registry"),
            ):
                if self.api.request("GET", self.path(kind, name)) is not None:
                    raise ValueError("retained installation state is missing; refusing reinitialization")
            metadata = self._metadata(self.name + "-state")
            del metadata["annotations"][PREFIX + "writer-generation"]
            self._desired()
            try:
                current = self.api.request("POST", self.path("ConfigMap"), {
                    "apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "data": {},
                })
            except Conflict:
                current = self.api.request("GET", self.state_path)
                if current is None:
                    raise Conflict("concurrent installation state is unavailable") from None
        if (current["metadata"].get("namespace") != self.namespace
                or current["metadata"].get("annotations", {}).get(PREFIX + "installation-uid") != self.uid):
            raise ValueError("foreign retained installation state cannot be adopted")
        self.state_uid = current["metadata"]["uid"]

    def _fence(self):
        self._desired()
        current = self.api.request("GET", self.state_path)
        if (current is None or current["metadata"]["uid"] != self.state_uid
                or (self.generation is not None and current["metadata"].get("annotations", {}).get(
                    PREFIX + "writer-generation") != str(self.generation))):
            raise Conflict("retained installation writer changed")
        return current

    def _pin(self, name, value):
        for attempt in range(3):
            current = self._fence()
            recorded = current["metadata"].get("annotations", {}).get(PREFIX + name)
            if recorded is not None:
                if recorded != value:
                    raise ValueError("retained installation " + name + " requires explicit migration")
                return
            try:
                self.api.request(
                    "PATCH", self.state_path,
                    {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"],
                                  "annotations": {PREFIX + name: value}}},
                    content_type="application/merge-patch+json",
                )
                return
            except Conflict:
                if attempt == 2:
                    raise

    def _metadata(self, name):
        return {
            "name": name, "namespace": self.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "Guardd",
                PREFIX + "installation": hashlib.sha256(self.uid.encode()).hexdigest()[:16],
            },
            "annotations": {
                PREFIX + "installation-uid": self.uid, PREFIX + "writer-generation": str(self.generation),
            },
        }

    def _owned(self, current):
        annotations = current["metadata"].get("annotations", {})
        if (current["metadata"].get("namespace") != self.namespace
                or annotations.get(PREFIX + "installation-uid") != self.uid):
            raise ValueError("foreign installation resource cannot be adopted")
        try:
            generation = int(annotations[PREFIX + "writer-generation"])
        except (KeyError, ValueError):
            raise ValueError("installation resource has no valid writer generation") from None
        if generation < 1 or self.generation is None or generation > self.generation:
            raise Conflict("newer installation writer owns this resource")

    def _apply(self, kind, name, fields):
        for _ in range(3):
            current = self.api.request("GET", self.path(kind, name))
            desired = {
                "apiVersion": "apps/v1" if kind == "Deployment" else "v1",
                "kind": kind, "metadata": self._metadata(name), **fields,
            }
            if current is not None:
                self._owned(current)
                desired["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
            self._fence()
            try:
                if current is None:
                    return self.api.request(
                        "POST", self.path(kind) + "?fieldManager=guardd-installer", desired,
                    )
                return self.api.request(
                    "PATCH", self.path(kind, name) + "?fieldManager=guardd-installer",
                    desired, content_type="application/merge-patch+json",
                )
            except Conflict:
                if _ == 2:
                    raise
        raise Conflict("installation resource remained contended")

    def _admit_installation(self):
        if self.state_uid is None:
            self._load_state()
        digest = hashlib.sha256(self.raw.encode()).hexdigest()
        for attempt in range(3):
            current = self._fence()
            annotations = current["metadata"].get("annotations", {})
            recorded = annotations.get(PREFIX + "release-uid")
            if recorded is None and any(PREFIX + name in annotations for name in (
                    "writer-generation", "writer-config")):
                raise ValueError("retained installation release admission is missing")
            release = self.api.request("GET", self.path("ConfigMap", self.name + "-release"))
            if release is None:
                if recorded is None or self.config["enabled"]:
                    raise ValueError("Helm release incarnation marker is unavailable")
                expected = recorded
            else:
                self._helm_owned(release)
                expected = release["metadata"]["uid"]
            if (recorded is not None and recorded != expected
                    and self.config["existingInstallationUID"] != self.uid):
                raise ValueError("retained installation requires explicit existingInstallationUID")
            try:
                generation = int(annotations[PREFIX + "writer-generation"]) if recorded else 0
            except (KeyError, ValueError, TypeError):
                raise ValueError("retained installation has no valid writer generation") from None
            if recorded and generation < 1:
                raise ValueError("invalid retained installation writer generation")
            if recorded == expected and annotations.get(PREFIX + "writer-config") == digest:
                self.generation = generation
                return
            generation += 1
            try:
                self.api.request(
                    "PATCH", self.state_path,
                    {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"],
                                  "annotations": {
                                      PREFIX + "release-uid": expected,
                                      PREFIX + "writer-generation": str(generation),
                                      PREFIX + "writer-config": digest,
                                  }}},
                    content_type="application/merge-patch+json",
                )
                self.generation = generation
                return
            except Conflict:
                if attempt == 2:
                    raise

    def _authority(self):
        name = self.name + "-authority"
        current = self.api.request("GET", self.path("Secret", name))
        if current is None:
            if self._fence()["metadata"].get("annotations", {}).get(PREFIX + "authority"):
                raise ValueError("retained authority is missing; refusing replacement")
            key, certificate = issue(None, None, "Guardd " + self.uid)
            desired = {
                "apiVersion": "v1", "kind": "Secret", "metadata": self._metadata(name),
                "type": "Opaque", "immutable": True,
                "data": {"ca.key": encoded(pem_key(key)), "ca.crt": encoded(pem_certificate(certificate))},
            }
            self._fence()
            try:
                current = self.api.request(
                    "POST", self.path("Secret") + "?fieldManager=guardd-installer", desired,
                )
            except Conflict:
                current = self.api.request("GET", self.path("Secret", name))
                if current is None:
                    raise Conflict("concurrent authority creation has not become visible") from None
        self._owned(current)
        try:
            key = serialization.load_pem_private_key(b64decode(current["data"]["ca.key"], validate=True), None)
            certificate = x509.load_pem_x509_certificate(b64decode(current["data"]["ca.crt"], validate=True))
            certificate.verify_directly_issued_by(certificate)
            valid = (
                same_key(key, certificate)
                and certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                and certificate.not_valid_before_utc <= datetime.now(timezone.utc) < certificate.not_valid_after_utc
            )
        except (KeyError, ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
            raise ValueError("invalid retained installation authority") from None
        if not valid:
            raise ValueError("retained authority requires explicit operator migration")
        self._pin("authority", hashlib.sha256(pem_certificate(certificate)).hexdigest())
        return key, certificate

    def _identity(self, name, authority, alternative, usage, key_name, certificate_name, ca_name):
        key, root = authority
        current = self.api.request("GET", self.path("Secret", name))
        if current is not None:
            self._owned(current)
            try:
                private = serialization.load_pem_private_key(b64decode(current["data"][key_name], validate=True), None)
                certificate = x509.load_pem_x509_certificate(
                    b64decode(current["data"][certificate_name], validate=True),
                )
                certificate.verify_directly_issued_by(root)
                valid = (
                    same_key(private, certificate)
                    and certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    == x509.SubjectAlternativeName([alternative])
                    and list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [usage]
                    and not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                    and b64decode(current["data"][ca_name], validate=True) == pem_certificate(root)
                    and certificate.not_valid_before_utc <= datetime.now(timezone.utc)
                )
            except (KeyError, ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
                raise ValueError("invalid retained leaf identity: " + name) from None
            if not valid:
                raise ValueError("retained leaf identity does not match installation: " + name)
            if certificate.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=7):
                return
        private, certificate = issue(key, root, name, alternative, usage)
        self._apply("Secret", name, {
            "type": "Opaque", "data": {
                key_name: encoded(pem_key(private)), certificate_name: encoded(pem_certificate(certificate)),
                ca_name: encoded(pem_certificate(root)),
            },
        })

    def _route(self, node_name, node_uid):
        resource = self.name + "-n-" + hashlib.sha256(node_uid.encode()).hexdigest()[:16]
        server = resource + "." + self.namespace + ".svc"
        directory = self.config["controllerMountDirectory"]
        return {"nodeName": node_name, "nodeUID": node_uid, "providers": [{
            "name": "guardd", "endpoint": server + ":9444", "serverName": server,
            "caFile": directory + "/ca.pem", "certificateFile": directory + "/controller.pem",
            "keyFile": directory + "/controller-key.pem",
        }]}

    def _provider(self, route, authority, enroll):
        provider = route["providers"][0]
        resource = provider["serverName"].split(".")[0]
        self._identity(
            resource + "-tls", authority, x509.DNSName(provider["serverName"]),
            ExtendedKeyUsageOID.SERVER_AUTH, "server.key", "server.crt", "controller-ca.crt",
        )
        if not enroll:
            return
        labels = self._metadata(resource)["labels"] | {
            PREFIX + "node": hashlib.sha256(route["nodeUID"].encode()).hexdigest()[:16],
        }
        self._apply("Service", resource, {"spec": {
            "type": "ClusterIP", "selector": labels,
            "ports": [{"name": "grpc", "port": 9444, "targetPort": "grpc", "protocol": "TCP"}],
        }})
        state = (
            self.config["stateDirectory"] + "/" + hashlib.sha256(self.uid.encode()).hexdigest()
            + "/" + hashlib.sha256(route["nodeUID"].encode()).hexdigest()
        )
        configuration = {
            "listen": "0.0.0.0:9444", "state": "/var/lib/guardd/provider.db",
            "pins": "/sys/fs/bpf/guardd/" + hashlib.sha256(state.encode()).hexdigest(),
            "filesystemObject": "/opt/guardd/filesystem.bpf.o",
            "containerObject": "/opt/guardd/container.bpf.o",
            "nodeName": route["nodeName"], "nodeUID": route["nodeUID"],
            "criCommand": ["/usr/local/bin/crictl", "--runtime-endpoint",
                           "unix:///run/guardd-cri/" + self.config["criSocketName"]],
            "tls": {"certificate": "/etc/guardd/tls/server.crt",
                    "privateKey": "/etc/guardd/tls/server.key",
                    "clientCA": "/etc/guardd/tls/controller-ca.crt"},
            "allowedClientIdentities": [self.config["controllerIdentity"]],
        }
        self._apply("ConfigMap", resource + "-config", {
            "data": {"provider.json": json.dumps(configuration, sort_keys=True, separators=(",", ":"))},
        })
        volumes = [
            {"name": "config", "configMap": {"name": resource + "-config", "defaultMode": 256}},
            {"name": "tls", "secret": {"secretName": resource + "-tls", "defaultMode": 256}},
            {"name": "state", "hostPath": {"path": state, "type": "DirectoryOrCreate"}},
            {"name": "bpf", "hostPath": {"path": "/sys/fs/bpf", "type": "Directory"}},
            {"name": "cgroup", "hostPath": {"path": "/sys/fs/cgroup", "type": "Directory"}},
            {"name": "cri", "hostPath": {"path": self.config["criSocketDirectory"], "type": "Directory"}},
        ]
        mounts = [
            {"name": "config", "mountPath": "/etc/guardd/config", "readOnly": True},
            {"name": "tls", "mountPath": "/etc/guardd/tls", "readOnly": True},
            {"name": "state", "mountPath": "/var/lib/guardd"},
            {"name": "bpf", "mountPath": "/sys/fs/bpf"},
            {"name": "cgroup", "mountPath": "/sys/fs/cgroup", "readOnly": True},
            {"name": "cri", "mountPath": "/run/guardd-cri", "readOnly": True},
        ]
        self._apply("Deployment", resource, {"spec": {
            "replicas": 1, "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": {
                "nodeName": route["nodeName"], "hostPID": True,
                "serviceAccountName": self.name + "-provider",
                "imagePullSecrets": [{"name": item} for item in self.config["imagePullSecrets"]],
                "containers": [{
                    "name": "guardd", "image": self.config["image"],
                    "imagePullPolicy": self.config["imagePullPolicy"],
                    "command": ["/usr/bin/nsenter", "--cgroup=/proc/1/ns/cgroup", "--",
                                "/opt/guardd/venv/bin/agentsuite-guardd"],
                    "args": ["--config", "/etc/guardd/config/provider.json", "serve-kubernetes-enforcement"],
                    "securityContext": {"privileged": True, "runAsUser": 0, "readOnlyRootFilesystem": True},
                    "ports": [{"name": "grpc", "containerPort": 9444}],
                    "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                  "limits": {"cpu": "1", "memory": "512Mi"}},
                    "volumeMounts": mounts,
                }], "volumes": volumes,
            }},
        }})

    def _routes(self, raw):
        if len(raw.encode()) > MAX_REGISTRY_BYTES:
            raise ValueError("retained registry exceeds capacity")
        routes = json.loads(raw)
        exact(routes, {"nodes"})
        if type(routes["nodes"]) is not list:
            raise ValueError("retained registry must contain Node records")
        known = {}
        for route in routes["nodes"]:
            if (type(route) is not dict or type(route.get("nodeName")) is not str
                    or type(route.get("nodeUID")) is not str
                    or route != self._route(route["nodeName"], route["nodeUID"])
                    or not route["nodeUID"] or route["nodeUID"] in known):
                raise ValueError("retained registry has changed or duplicate Node authority")
            known[route["nodeUID"]] = route
        return known

    def _history(self, known):
        for attempt in range(3):
            current = self._fence()
            retained = current.get("data", {}).get("registry.json")
            if retained is None:
                if current["metadata"].get("annotations", {}).get(PREFIX + "registry-present"):
                    raise ValueError("authoritative registry inventory is missing")
                retained = '{"nodes":[]}'
            for uid, route in self._routes(retained).items():
                if uid in known and known[uid] != route:
                    raise ValueError("existing Node authority cannot change")
                known[uid] = route
            routes = {"nodes": sorted(known.values(), key=lambda route: route["nodeUID"])}
            raw = json.dumps(routes, sort_keys=True, separators=(",", ":"))
            if len(raw.encode()) > MAX_REGISTRY_BYTES:
                raise ValueError("registry capacity exhausted; existing routes retained, new enrollment refused")
            if raw == retained:
                return routes, raw
            try:
                self.api.request(
                    "PATCH", self.state_path,
                    {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"],
                                  "annotations": {PREFIX + "registry-present": "true"}},
                     "data": {"registry.json": raw}},
                    content_type="application/merge-patch+json",
                )
                return routes, raw
            except Conflict:
                if attempt == 2:
                    raise
        raise Conflict("installation inventory remained contended")

    def run(self):
        self._admit_installation()
        enabled = self.config["enabled"]
        current = self._fence()
        history = current.get("data", {}).get("registry.json")
        if history is None and current["metadata"].get("annotations", {}).get(PREFIX + "registry-present"):
            raise ValueError("authoritative registry inventory is missing; refusing to discard history")
        existing = self.api.request("GET", self.path("ConfigMap", self.name + "-registry"))
        if existing is not None:
            self._owned(existing)
            if history is None:
                raise ValueError("retained registry has no authoritative installation inventory")
        if not enabled and history is None:
            return {"installation": self.uid, "enrollment": False, "nodes": 0}
        frozen = {key: self.config[key] for key in (
            "criSocketDirectory", "criSocketName", "stateDirectory",
            "controllerIdentity", "controllerMountDirectory",
        )}
        self._pin("physical-settings", hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest())
        authority = self._authority()
        known = self._routes(history if history is not None else '{"nodes":[]}')
        if existing is not None:
            for uid, route in self._routes(existing["data"]["registry.json"]).items():
                if known.get(uid) != route:
                    raise ValueError("projected registry contradicts retained installation inventory")
        # Discovery and enrollment refusal must never starve retained cleanup credentials.
        if known:
            self._identity(
                self.name + "-controller-identity", authority,
                x509.UniformResourceIdentifier(self.config["controllerIdentity"]),
                ExtendedKeyUsageOID.CLIENT_AUTH, "controller-key.pem", "controller.pem", "ca.pem",
            )
            for route in known.values():
                self._provider(route, authority, False)
        selected = set()
        if enabled:
            nodes = self.api.request("GET", "/api/v1/nodes?limit=1000")
            if nodes is None or nodes.get("metadata", {}).get("continue"):
                raise ValueError("Node discovery exceeds finite installation bound")
            for node in nodes["items"]:
                metadata = node["metadata"]
                if metadata.get("deletionTimestamp"):
                    continue
                labels = metadata.get("labels", {})
                if not all(labels.get(k) == v for k, v in self.config["nodeSelector"].items()):
                    continue
                route = self._route(metadata["name"], metadata["uid"])
                if metadata["uid"] in known and known[metadata["uid"]] != route:
                    raise ValueError("Node UID changed its registered name")
                known[metadata["uid"]] = route
                selected.add(metadata["uid"])
        routes, raw = self._history(known)
        if not routes["nodes"]:
            raise ValueError("no selected linux/amd64 Nodes available for installation")
        self._identity(
            self.name + "-controller-identity", authority,
            x509.UniformResourceIdentifier(self.config["controllerIdentity"]),
            ExtendedKeyUsageOID.CLIENT_AUTH, "controller-key.pem", "controller.pem", "ca.pem",
        )
        for route in routes["nodes"]:
            self._provider(route, authority, route["nodeUID"] in selected)
        self._apply("ConfigMap", self.name + "-registry", {"data": {"registry.json": raw}})
        return {"installation": self.uid, "enrollment": enabled, "nodes": len(routes["nodes"])}


def reconcile(namespace, name, *, disable_enrollment=False):
    api = KubernetesAPI()
    installation = Installation(api, namespace, name)
    if disable_enrollment:
        for attempt in range(3):
            current = installation._desired()
            config = installation.config | {"enabled": False}
            try:
                api.request(
                    "PATCH", installation.anchor_path,
                    {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]},
                     "data": {"config.json": json.dumps(config, sort_keys=True, separators=(",", ":"))}},
                    content_type="application/merge-patch+json",
                )
                break
            except Conflict:
                if attempt == 2:
                    raise
        installation = Installation(api, namespace, name)
    return installation.run()
