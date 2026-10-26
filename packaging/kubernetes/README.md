# Kubernetes provider image (experimental)

This is the container `serve-kubernetes-enforcement` image, not the
historical signed service or its host installer. It bundles Python, libbpf,
bpftool, CO-RE filesystem and combined network/filesystem objects, crictl and
nsenter. It contains no policy,
credentials, runtime socket, automatically attached controls or live-state
database. Packaging is not enforcement or product-qualification evidence.

The optional [shared Helm installation](../../charts/guardd/README.md) uses this
same image for finite bootstrap/renewal jobs and the per-Node providers.

## Private developer build

Use BuildKit with named contexts. The initial qualified platform is
`linux/amd64`; other architectures deliberately refuse this build. Supply a
private input directory containing:

- `vmlinux.h`, generated with
  `bpftool btf dump file /sys/kernel/btf/vmlinux format c` from the explicitly
  selected qualification kernel.
- `crictl`, the native standalone binary for the selected platform, with its
  SHA256 independently verified against a trusted release record. Do not supply
  a shell wrapper or a symlink into a host installation.

From the repository root, substitute explicit trusted values:

```sh
docker buildx build --platform linux/amd64 \
  --build-context guardd_inputs=/absolute/private/guardd-inputs \
  --build-arg BASE_IMAGE=debian@sha256:<verified-base-manifest-digest> \
  --build-arg CRICTL_SHA256=<verified-lowercase-binary-sha256> \
  --build-arg SOURCE_DATE_EPOCH=<recorded-source-epoch> \
  -f packaging/kubernetes/Dockerfile \
  --tag localhost/guardd:kubernetes-local \
  --output type=oci,dest=/absolute/private/guardd-kubernetes.oci.tar .
```

Do not add `--push`. On shared hosts use an explicitly resource-capped BuildKit
builder; limiting only its Docker client does not limit daemon-owned build
processes. The input directory must contain only the two non-secret inputs.
The Docker context allowlist excludes Git state, tests, local credentials and
unrelated artifacts. The build verifies the actual copied crictl bytes, rather
than trusting a pre-copy check.

The image retains source-file hashes (including local modifications), native
input/object hashes, epoch, and actual build/runtime package versions under
`/usr/local/share/guardd/build/`. Retain the OCI archive and its exact manifest
digest with these records. A base digest and fixed epoch alone do **not** make
apt or Python dependency resolution reproducible. Reusing the accepted OCI
artifact preserves those exact resolved bytes; rebuilding reproducibly also
requires retaining or pinning the dependency artifacts. No publication is
necessary to import the archive into the selected private container runtime.

For an unpublished K3s import, register the exact repository-digest reference
that Pods will use, not just the archive's tag:

```sh
sudo k3s ctr -n k8s.io images import --digests /absolute/private/guardd-kubernetes.oci.tar
sudo k3s ctr -n k8s.io images tag localhost/guardd:kubernetes-local \
  localhost/guardd@sha256:<recorded-containerimage.digest>
sudo k3s crictl inspecti localhost/guardd@sha256:<recorded-containerimage.digest>
```

Check that CRI reports that exact `repoDigests` entry before installing with
`imagePullPolicy=Never`. Importing the tag alone can leave `repoDigests` empty
even with `ctr --digests`; a digest-pinned Pod then correctly fails
`ErrImageNeverPull`. Tagging the imported bytes adds local reference metadata;
it neither changes the image nor publishes anything.

The BTF input selects a build reference, not universal kernel compatibility.
The real provider must establish and independently read back controls on the
actual target before Orka may release it. No extra installer kernel
certification or boot-setting mutation is implied.

## Provider Pod boundary

The installer must supply the root-owned configuration and mTLS Secret
described in [the provider protocol](../../docs/PROTOCOL.md#kubernetes-container-provider).
Use `/opt/guardd/filesystem.bpf.o` as `filesystemObject` and
`/opt/guardd/container.bpf.o` as `containerObject`, with
`/usr/local/bin/crictl` in `criCommand`, with an explicit mounted CRI endpoint.

The trusted node-management Pod needs host PID visibility, the complete host
cgroup hierarchy, bpffs, durable private host state, the selected runtime
socket, and sufficient management privileges. None belongs in the governed
workload. `hostPID: true` alone does not select the host cgroup namespace.
The provider command must enter that namespace explicitly before starting:

```text
/usr/bin/nsenter --cgroup=/proc/1/ns/cgroup --
  /opt/guardd/venv/bin/agentsuite-guardd
  --config /etc/guardd/provider.json serve-kubernetes-enforcement
```

Provision a real bpffs mount at `/sys/fs/bpf` in the selected Node's mount
namespace before enrollment. A Docker host's bpffs does not imply that a nested
kind node has one; an ordinary read-only sysfs directory is not sufficient.
Use the Node's normal host provisioning mechanism, not a workload or an
enforcement-proof fallback. Enrollment success does not attest this prerequisite.

Supply the host hierarchy mount without a cgroup subtree restriction. Mount
the selected runtime's socket directory read-only rather than binding a
single replaceable socket inode. The configuration must pin the expected
Node UID and use separately authenticated per-incarnation routing; a shared
load-balanced endpoint is not an exact Node identity.

Do not run the legacy `load-gadget.sh` as an init container: this provider
owns its private per-binding native objects and durable retirement. Pod
readiness, a working TLS endpoint, or a successful image build is not a Task
`ENFORCED` result.
