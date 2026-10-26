# Guardd Kubernetes installation (experimental)

This optional chart uses the same Guardd image for finite bootstrap and periodic
reconciliation. It has no controller or policy of its own. It installs one
privileged provider per selected physical Node incarnation. Only a provider's
fresh, target-specific proof permits Orka to release a protected container.
Successful Helm installation is not an enforcement qualification.

Default `enabled: false` installs no management or privileged resource graph.
Enable explicitly with an independently qualified digest-pinned image, appropriate
CRI socket directory/name and a namespace that admits the required management
privileges. Use normal `helm upgrade --install --wait --wait-for-jobs`; the
bootstrap Job is not a post-install hook.

```sh
helm upgrade --install private-guardd ./charts/guardd \
  --namespace management --create-namespace \
  --set enabled=true \
  --set image=private/guardd@sha256:<qualified-manifest-digest> \
  --set criSocketDirectory=/run/k3s/containerd \
  --wait --wait-for-jobs
```

The installation name is deterministic from the Helm release, or an explicitly
set DNS label of at most 39 characters. Treat its name, namespace, selected CRI,
state root, controller URI and controller credential mount directory as
installation identities: do not change them to escape retained obligations.
The installer refuses physical-setting changes rather than migrating silently.
The optional Orka composition uses this chart directly, not duplicated templates.

## Retention and supported lifecycle

Disable new enrollment with a normal upgrade setting `enabled=false`, retaining
the same image and physical settings. Server-side Helm lookup includes the
retained installation even when disabled. Existing providers, trust, exact
Node-incarnation routes, management RBAC and five-minute renewal remain.
Disappearing Nodes are never automatically deleted or assigned replacement
incarnations. Added routes are bounded; reaching capacity refuses enrollment
without dropping history. The authoritative inventory lives in the retained
installer-owned `<installation>-state` ConfigMap; the projected registry can be
reconstructed from it. Runtime inventory, trust pins and admission generations
never enter Helm-owned desired configuration: reinstallation may replay that
configuration without erasing durable runtime state.

Uninstall's pre-delete Job disables enrollment before Helm removes release
records. The retained CronJob continues renewing existing identities, and the
providers' host state is not removed. Do not skip uninstall hooks. This deliberately
leaves management resources and privileges: uninstall is not decommission.
There is no automatic decommission or garbage collection while bindings may remain.
Reinstallation over retained state requires the exact `existingInstallationUID`
from the installation ConfigMap's `metadata.uid`; foreign state is never adopted.
An ordinary Helm-owned, non-retained release ConfigMap identifies each release
incarnation independently of Helm history retention. Admission checks it on
upgrades too, so upgrading a failed reinstall cannot bypass explicit acceptance.
The retained state allocates its own monotonic writer generation: Helm's revision
counter resetting to one on reinstallation cannot invalidate retained resources.

Use `helm upgrade` with a previous **compatible** chart/controller version for a
rollback: it supplies a fresh writer generation and current enrollment intent.
Raw `helm rollback` replays historical manifests and is not a supported migration
of this retained installation. Downgrading to software that predates enforcement,
deleting the namespace/state/trust, disabling renewal, and bypassing lifecycle hooks
are trusted-administrator destructive actions, not continuity guarantees.

## Credentials and controller integration

The installer creates a private immutable CA Secret, a renewable controller Secret,
and per-Node renewable server Secrets. No certificate/key generation occurs in Helm
templates. Corrupt or missing pinned authority fails explicitly; it is not replaced.
The provider's full projected config/Secret volumes use root-only files and the
provider explicitly enters the host cgroup namespace. Leaf renewal does not change
its Pod template. Its single-replica Deployment uses `Recreate` for exclusive
durable-state ownership.

Mount `<installation>-registry` (`registry.json`) and
`<installation>-controller-identity` (`ca.pem`, `controller.pem`,
`controller-key.pem`) as full projected volumes into the trusted controller at
`controllerMountDirectory`. Never use `subPath`. A non-root controller needs its
ordinary `fsGroup` and group-readable key projection; provider keys stay root-only.
Keep this controller mount available after disabling enrollment, including for
retirement. Guardd's host mounts, CA signing key and Kubernetes management service
accounts must never enter workload containers.

Bootstrap/renewal jobs are finite and resource-bounded. They require namespace-local
get/create/patch of their managed resource kinds, plus cluster-wide read-only Node
discovery. Provider service accounts can only GET Nodes. The management namespace
is a trusted administrative boundary, not a tenant sandbox. Monitor failed
bootstrap/renewal Jobs and retain their sanitized diagnostics; TLS availability
does not imply a workload has been enforced.
New-Node discovery or enrollment-capacity refusal still fails the Job visibly,
but only after renewing validated retained identities. An enrollment limit must
not starve existing cleanup credentials.
