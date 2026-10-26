"""Drive finite installation, retained authority, generation and restart safety."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest

from agentsuite_guardd.kubernetes_api import Conflict
from agentsuite_guardd.kubernetes_install import Installation, PREFIX, reconcile


class API:
    def __init__(self):
        self.objects = {}
        self.writes = []
        self.counter = 0
        self.nodes = []
        self.before_write = None

    def request(self, method, url, body=None, **_options):
        path = urlsplit(url).path
        if path == "/api/v1/nodes":
            return {"metadata": {}, "items": deepcopy(self.nodes)}
        if method == "GET":
            return deepcopy(self.objects.get(path))
        if self.before_write:
            self.before_write(path)
        body = deepcopy(body)
        if method == "POST":
            path += "/" + body["metadata"]["name"]
            if path in self.objects:
                raise Conflict("already created")
        existing = self.objects.get(path)
        if existing:
            if body["metadata"].get("resourceVersion") != existing["metadata"]["resourceVersion"]:
                raise Conflict("resource changed")
            if existing.get("immutable") and "data" in body and existing["data"] != body["data"]:
                raise ValueError("immutable Secret cannot change")
        self.counter += 1
        result = deepcopy(existing or {})
        for key, value in body.items():
            if key in ("metadata", "data"):
                result.setdefault(key, {})
                for field, nested in value.items():
                    if key == "metadata" and field in ("annotations", "labels"):
                        result[key].setdefault(field, {}).update(nested)
                    else:
                        result[key][field] = nested
            else:
                result[key] = value
        result["metadata"]["resourceVersion"] = str(self.counter)
        result["metadata"].setdefault("uid", "created-" + str(self.counter))
        self.objects[path] = result
        self.writes.append((method, path))
        return deepcopy(result)


def configuration():
    return {
        "releaseName": "orka", "releaseNamespace": "management", "revision": 1, "isInstall": True,
        "enabled": True, "existingInstallationUID": "",
        "image": "private/guardd@sha256:" + "a" * 64, "imagePullPolicy": "IfNotPresent",
        "criSocketDirectory": "/run/containerd", "criSocketName": "containerd.sock",
        "stateDirectory": "/var/lib/guardd", "controllerIdentity": "spiffe://orka.ai/controller",
        "controllerMountDirectory": "/var/run/orka/enforcement",
        "nodeSelector": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"},
        "imagePullSecrets": [],
    }


def setup():
    api = API()
    config = configuration()
    anchor = "/api/v1/namespaces/management/configmaps/test-installation"
    api.objects[anchor] = {
        "metadata": {
            "name": "test-installation", "namespace": "management", "uid": "installation-uid",
            "resourceVersion": "0", "labels": {"app.kubernetes.io/managed-by": "Helm"},
            "annotations": {"meta.helm.sh/release-name": "orka", "meta.helm.sh/release-namespace": "management"},
        }, "data": {"config.json": json.dumps(config)},
    }
    marker = deepcopy(api.objects[anchor])
    marker["metadata"].update(name="test-release", uid="helm-install-uid")
    marker["data"] = {}
    api.objects["/api/v1/namespaces/management/configmaps/test-release"] = marker
    api.nodes = [{"metadata": {
        "name": "worker", "uid": "node-one",
        "labels": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"},
    }}]
    return api, anchor, config


def run(api):
    return Installation(api, "management", "test").run()


def protected_objects(api, anchor):
    return {path: deepcopy(value) for path, value in api.objects.items()
            if path not in (anchor, "/api/v1/namespaces/management/configmaps/test-state")}


def retained(api):
    return api.objects["/api/v1/namespaces/management/configmaps/test-state"]


def test_finite_reconcile_reuses_trust_and_retains_old_node_state():
    api, anchor, _ = setup()
    assert run(api)["nodes"] == 1
    authority = deepcopy(api.objects["/api/v1/namespaces/management/secrets/test-authority"])
    deployments = {path: deepcopy(value["spec"]) for path, value in api.objects.items() if "/deployments/" in path}
    identities = {path: deepcopy(value["data"]) for path, value in api.objects.items() if "/secrets/" in path and "data" in value}
    assert run(api)["nodes"] == 1
    assert api.objects["/api/v1/namespaces/management/secrets/test-authority"] == authority
    assert identities == {path: value["data"] for path, value in api.objects.items() if "/secrets/" in path and "data" in value}
    api.nodes[0]["metadata"]["uid"] = "node-two"
    assert run(api)["nodes"] == 2
    for path, spec in deployments.items():
        assert api.objects[path]["spec"] == spec
    routes = json.loads(retained(api)["data"]["registry.json"])["nodes"]
    assert {route["nodeUID"] for route in routes} == {"node-one", "node-two"}


def test_renewal_and_disabled_enrollment_do_not_roll_provider_templates():
    api, anchor, config = setup()
    run(api)
    deployment_specs = {path: deepcopy(obj["spec"]) for path, obj in api.objects.items() if "/deployments/" in path}
    client_path = "/api/v1/namespaces/management/secrets/test-controller-identity"
    original = api.objects[client_path]["data"]["controller.pem"]
    now = datetime.now(timezone.utc) + timedelta(days=24)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    config.update(enabled=False, revision=2, isInstall=False)
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    api.nodes[0]["metadata"]["uid"] = "not-enrolled"
    with patch("agentsuite_guardd.kubernetes_install.datetime", Later):
        assert run(api) == {"installation": "installation-uid", "enrollment": False, "nodes": 1}
    assert api.objects[client_path]["data"]["controller.pem"] != original
    assert deployment_specs == {path: obj["spec"] for path, obj in api.objects.items() if "/deployments/" in path}


@pytest.mark.parametrize("missing", ["authority", "inventory"])
def test_missing_retained_authority_or_inventory_never_reinitializes(missing):
    api, anchor, _ = setup()
    run(api)
    if missing == "authority":
        del api.objects["/api/v1/namespaces/management/secrets/test-authority"]
    else:
        del retained(api)["data"]["registry.json"]
        del api.objects["/api/v1/namespaces/management/configmaps/test-registry"]
    original = protected_objects(api, anchor)
    inventory = deepcopy(retained(api)["data"])
    with pytest.raises(ValueError):
        run(api)
    assert protected_objects(api, anchor) == original
    assert retained(api)["data"] == inventory


def test_projected_registry_can_be_recovered_from_authoritative_history():
    api, _anchor, _ = setup()
    run(api)
    path = "/api/v1/namespaces/management/configmaps/test-registry"
    original = deepcopy(api.objects[path]["data"])
    del api.objects[path]
    api.nodes = []
    assert run(api)["nodes"] == 1
    assert api.objects[path]["data"] == original


def test_foreign_resources_and_retained_release_takeover_refuse():
    api, anchor, _ = setup()
    foreign = "/api/v1/namespaces/management/secrets/test-authority"
    api.objects[foreign] = {"metadata": {"namespace": "management", "annotations": {}}}
    with pytest.raises(ValueError):
        run(api)
    del api.objects[foreign]
    run(api)
    api.objects["/api/v1/namespaces/management/configmaps/test-release"]["metadata"]["uid"] = "different-helm-install"
    original = protected_objects(api, anchor)
    admitted = retained(api)["metadata"]["annotations"][PREFIX + "release-uid"]
    with pytest.raises(ValueError):
        run(api)
    assert protected_objects(api, anchor) == original
    assert retained(api)["metadata"]["annotations"][PREFIX + "release-uid"] == admitted


def test_stale_writer_cannot_change_retained_provider_state():
    api, anchor, config = setup()
    run(api)
    stale = Installation(api, "management", "test")
    config.update(revision=2, isInstall=False)
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    original = protected_objects(api, anchor)
    with pytest.raises(Conflict):
        stale.run()
    assert protected_objects(api, anchor) == original


def test_physical_migration_cannot_repoint_retained_state_or_authority():
    api, anchor, config = setup()
    run(api)
    original = protected_objects(api, anchor)
    physical = retained(api)["metadata"]["annotations"][PREFIX + "physical-settings"]
    config["stateDirectory"] = "/different-state"
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    with pytest.raises(ValueError):
        run(api)
    assert protected_objects(api, anchor) == original
    assert retained(api)["metadata"]["annotations"][PREFIX + "physical-settings"] == physical


def test_capacity_failure_preserves_published_registry():
    api, _anchor, _ = setup()
    run(api)
    path = "/api/v1/namespaces/management/configmaps/test-registry"
    original = deepcopy(api.objects[path]["data"])
    api.nodes[0]["metadata"]["uid"] = "new-node"
    with patch("agentsuite_guardd.kubernetes_install.MAX_REGISTRY_BYTES", len(original["registry.json"].encode()) + 1):
        with pytest.raises(ValueError):
            run(api)
    assert api.objects[path]["data"] == original


def test_first_enable_during_upgrade_does_not_require_expired_helm_history():
    api, anchor, config = setup()
    config.update(revision=12, isInstall=False)
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    assert run(api)["nodes"] == 1


def test_uninstall_stop_preserves_renewal_after_helm_release_is_removed():
    api, anchor, _ = setup()
    run(api)
    with patch("agentsuite_guardd.kubernetes_install.KubernetesAPI", return_value=api):
        assert reconcile("management", "test", disable_enrollment=True)["enrollment"] is False
    assert json.loads(api.objects[anchor]["data"]["config.json"])["enabled"] is False
    del api.objects["/api/v1/namespaces/management/configmaps/test-release"]
    assert run(api) == {"installation": "installation-uid", "enrollment": False, "nodes": 1}


@pytest.mark.parametrize("name,field", [
    ("test-authority", "ca.crt"),
    ("test-controller-identity", "controller-key.pem"),
])
def test_corrupt_retained_credentials_refuse_without_replacement(name, field):
    api, _anchor, _ = setup()
    run(api)
    path = "/api/v1/namespaces/management/secrets/" + name
    api.objects[path]["data"][field] = "bm90LWEtY2VydGlmaWNhdGU="
    original = deepcopy(api.objects[path]["data"])
    with pytest.raises(ValueError):
        run(api)
    assert api.objects[path]["data"] == original


def test_concurrent_ca_creator_is_used_without_replacing_its_private_root():
    api, _anchor, _ = setup()
    loser = Installation(api, "management", "test")
    path = "/api/v1/namespaces/management/secrets"

    def winner_at_create(resource):
        if resource != path:
            return
        api.before_write = None
        run(api)

    api.before_write = winner_at_create
    assert loser.run()["nodes"] == 1
    authority = api.objects[path + "/test-authority"]
    assert authority["immutable"] is True
    assert len([write for write in api.writes if write == ("POST", path + "/test-authority")]) == 1


def test_contradictory_projection_never_silently_discards_authority():
    api, _anchor, _ = setup()
    run(api)
    path = "/api/v1/namespaces/management/configmaps/test-registry"
    registry = json.loads(api.objects[path]["data"]["registry.json"])
    registry["nodes"][0]["providers"][0]["endpoint"] = "unrecorded.invalid:9444"
    api.objects[path]["data"]["registry.json"] = json.dumps(registry)
    original = deepcopy(api.objects[path]["data"])
    with pytest.raises(ValueError):
        run(api)
    assert api.objects[path]["data"] == original


def test_explicit_retained_installation_recovery_and_ordinary_cas_retry():
    api, anchor, config = setup()
    run(api)
    api.objects["/api/v1/namespaces/management/configmaps/test-release"]["metadata"]["uid"] = "new-helm-install"
    config["existingInstallationUID"] = "installation-uid"
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    conflicted = []

    def change_once(path):
        if path != "/api/v1/namespaces/management/configmaps/test-state":
            return
        api.before_write = None
        retained(api)["metadata"]["resourceVersion"] = "concurrent-update"
        conflicted.append(True)

    api.before_write = change_once
    assert run(api)["nodes"] == 1
    assert conflicted
    # A later conflict in an ordinary managed-resource apply is retried locally.
    target = "/api/v1/namespaces/management/configmaps/test-registry"

    def ordinary_conflict(path):
        if path == target:
            api.before_write = None
            api.objects[path]["metadata"]["resourceVersion"] = "projection-updated"

    api.before_write = ordinary_conflict
    assert run(api)["nodes"] == 1


def test_reinstallation_generation_survives_helm_revision_reset():
    api, anchor, config = setup()
    run(api)
    config.update(revision=5, isInstall=False)
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    run(api)
    previous = int(retained(api)["metadata"]["annotations"][PREFIX + "writer-generation"])
    authority = deepcopy(api.objects["/api/v1/namespaces/management/secrets/test-authority"]["data"])
    config.update(revision=1, isInstall=True, existingInstallationUID="installation-uid")
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    api.objects["/api/v1/namespaces/management/configmaps/test-release"]["metadata"]["uid"] = "reinstalled"
    assert run(api)["nodes"] == 1
    assert int(retained(api)["metadata"]["annotations"][PREFIX + "writer-generation"]) > previous
    assert api.objects["/api/v1/namespaces/management/secrets/test-authority"]["data"] == authority


def test_failed_reinstall_cannot_bypass_admission_by_upgrading():
    api, anchor, config = setup()
    run(api)
    api.objects["/api/v1/namespaces/management/configmaps/test-release"]["metadata"]["uid"] = "unaccepted-reinstall"
    for revision, is_install in ((1, True), (2, False)):
        config.update(revision=revision, isInstall=is_install)
        api.objects[anchor]["data"]["config.json"] = json.dumps(config)
        with pytest.raises(ValueError):
            run(api)


@pytest.mark.parametrize("blocker", ["capacity", "discovery"])
def test_enrollment_refusal_does_not_starve_retained_leaf_renewal(blocker):
    api, _anchor, _ = setup()
    run(api)
    client_path = "/api/v1/namespaces/management/secrets/test-controller-identity"
    original = api.objects[client_path]["data"]["controller.pem"]
    now = datetime.now(timezone.utc) + timedelta(days=24)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    api.nodes[0]["metadata"]["uid"] = "additional-node"
    original_request = api.request

    def request(method, path, *args, **kwargs):
        response = original_request(method, path, *args, **kwargs)
        if blocker == "discovery" and path.startswith("/api/v1/nodes?"):
            response["metadata"]["continue"] = "next-page"
        return response

    api.request = request
    registry = api.objects["/api/v1/namespaces/management/configmaps/test-registry"]["data"]["registry.json"]
    limit = len(registry.encode()) + 1 if blocker == "capacity" else 512 << 10
    with patch("agentsuite_guardd.kubernetes_install.datetime", Later):
        with patch("agentsuite_guardd.kubernetes_install.MAX_REGISTRY_BYTES", limit):
            with pytest.raises(ValueError):
                run(api)
    assert api.objects[client_path]["data"]["controller.pem"] != original
    assert api.objects["/api/v1/namespaces/management/configmaps/test-registry"]["data"]["registry.json"] == registry


def test_late_creation_cannot_overwrite_a_newer_writer():
    api, anchor, config = setup()
    old = Installation(api, "management", "test")
    old._admit_installation()
    collection = "/api/v1/namespaces/management/configmaps"
    resource = collection + "/test-late"

    def new_writer_creates_first(path):
        if path != collection:
            return
        api.before_write = None
        config.update(revision=2, isInstall=False)
        api.objects[anchor]["data"]["config.json"] = json.dumps(config)
        new = Installation(api, "management", "test")
        new._admit_installation()
        new._apply("ConfigMap", "test-late", {"data": {"authority": "new"}})

    api.before_write = new_writer_creates_first
    with pytest.raises(Conflict):
        old._apply("ConfigMap", "test-late", {"data": {"authority": "stale"}})
    assert api.objects[resource]["data"] == {"authority": "new"}
    generation = api.objects[resource]["metadata"]["annotations"][PREFIX + "writer-generation"]
    assert int(generation) > old.generation
    assert generation == retained(api)["metadata"]["annotations"][PREFIX + "writer-generation"]


def test_runtime_inventory_never_becomes_helm_managed_configuration():
    api, anchor, config = setup()
    desired = deepcopy(api.objects[anchor])
    run(api)
    assert api.objects[anchor] == desired
    state_uid = retained(api)["metadata"]["uid"]
    inventory = deepcopy(retained(api)["data"])
    # Reinstall may replay only the original Helm-owned fields, not runtime state.
    api.objects[anchor] = desired
    config.update(revision=1, isInstall=True, existingInstallationUID="installation-uid")
    api.objects[anchor]["data"]["config.json"] = json.dumps(config)
    api.objects["/api/v1/namespaces/management/configmaps/test-release"]["metadata"]["uid"] = "reinstalled"
    assert run(api)["nodes"] == 1
    assert retained(api)["metadata"]["uid"] == state_uid
    assert retained(api)["data"] == inventory


def test_lost_runtime_state_cannot_initialize_over_live_credentials():
    api, _anchor, _ = setup()
    run(api)
    path = "/api/v1/namespaces/management/configmaps/test-state"
    del api.objects[path]
    authority = deepcopy(api.objects["/api/v1/namespaces/management/secrets/test-authority"])
    with pytest.raises(ValueError):
        run(api)
    assert path not in api.objects
    assert api.objects["/api/v1/namespaces/management/secrets/test-authority"] == authority
