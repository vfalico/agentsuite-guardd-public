# Provider protocol

## Kubernetes container provider

`agentsuite-guardd --config /absolute/private/kubernetes.json serve-kubernetes-enforcement`
serves the generic `orka.enforcement.v1.EnforcementProvider` gRPC service.
Canonical protobuf source belongs to Orka at
`proto/orka_enforcement/v1/enforcement.proto`; generated Python bindings live
in this package under `orka_enforcement.v1`. This lane does not require a
historical signing seed or Unix client socket.

Example complete root-owned, non-group/world-writable configuration:

```json
{
  "listen": "0.0.0.0:9444",
  "state": "/var/lib/agentsuite-guardd/kubernetes.db",
  "pins": "/sys/fs/bpf/agentsuite-guardd-kubernetes",
  "filesystemObject": "/opt/agentsuite-guardd/filesystem.bpf.o",
  "containerObject": "/opt/agentsuite-guardd/container.bpf.o",
  "nodeName": "",
  "nodeUID": "",
  "criCommand": ["/usr/local/bin/crictl"],
  "tls": {
    "certificate": "/etc/agentsuite-guardd/tls/server.crt",
    "privateKey": "/etc/agentsuite-guardd/tls/server.key",
    "clientCA": "/etc/agentsuite-guardd/tls/controller-ca.crt"
  },
  "allowedClientIdentities": ["spiffe://orka.ai/controller"]
}
```

Empty `nodeName` uses `GUARDD_NODE_NAME`. The daemon always verifies its actual
node UID through the authenticated Kubernetes API using the mounted ServiceAccount
token and CA; a nonempty expected `nodeUID` must additionally match. The
ServiceAccount needs `get` on the selected Node. TLS keys must be root-owned
regular files with no group/other permissions; root-owned projected Secret
symlinks are supported. Client certificates must chain to the configured CA
**and** have an explicitly allowed SAN. Workload containers receive neither
provider credentials nor CRI access.

The live listener reloads its server leaf key/certificate on new TLS
connections, so renewing a projected Secret does not restart the provider or
its protected workloads. A mismatched key pair, unsafe private-key permissions,
or unreadable replacement is logged and retains the last authenticated
configuration; clients still enforce certificate validity. The client CA is
pinned at startup: changing that trust requires explicit migration, not an
implicit credential renewal. Mount complete Secret volumes, not `subPath`
files, so Kubernetes can project updates.

`EnsureEnforced` accepts one binding ID, complete immutable requirement and
versioned target facts. This adapter accepts canonical JSON facts with exactly
`nodeName,nodeUID,namespace,podName,podUID,containerName,containerID` under
`orka.kubernetes-container/v1`; the ID must be the full `containerd://` ID.
It verifies CRI ownership, kernel identity and isolation independently.
Successful repeated Ensure freshly reads existing controls, including after
restart; it does not repeat singleton bootstrap activation. Evidence binds the
request's deterministic protobuf digests, exact physical target and readback.
Mandatory-provider composition is the runtime's responsibility.

The RPC outcomes are explicit pending, enforced or refused. Transport failures
are uncertainty, never admission or physical absence. Policy is opaque unchanged
bytes; this provider supports complete `agentsuite.policy/v1` filesystem
requirements and [combined `agentsuite.policy/v3` policies](CONTAINER_POLICY.md)
when their respective native objects are configured. The optional
`containerObject` does not upgrade existing policies or add runtime exceptions.
Refusal messages are at most 4096 UTF-8 bytes. Full readback remains
in the provider response/store, not Kubernetes annotations.
Provider-local refusal logs identify the operation, bounded binding ID,
exception class and innermost source location. They omit exception prose,
policy bytes, credentials and frame locals; RPC refusal outcomes are unchanged.

After exact CRI container ID, name and Pod ownership validation, a created or
exited incarnation returns pending without activation, live proof or cleanup.
An exit can precede Kubernetes Pod/Job status; the runtime remains responsible
for observing failure, retiring the old binding and selecting any retry.
Unknown CRI states and identity mismatches still refuse. A pending Ensure never
substitutes for the independent stopped-target fence required by Retire.
After live resolution, the held pidfd is checked before enforcement and after
successful readback. A positively observed root-process exit returns pending,
including a native lifetime failure during readback. Other identity, ownership
and policy failures still refuse, even when an exit is concurrent; an unreadable
lifetime observation remains uncertainty. The final check is an observation,
not an atomic fence against a later exit or proof that every cgroup member stopped.
This also covers an independently removed held cgroup and a matching-kind/hook
cgroup link reporting target ID zero after that exact cgroup's removal.
Wrong nonzero targets, link kinds and hooks remain integrity failures.
The same lifetime guard applies while constructing the resolved target.

`RetireEnforcement(bindingID)` does not stop a container. It returns pending
while the physical target lives. An exact held kernel-removed cgroup FD can
authorize cleanup. After losing that handle, successful exact-ID CRI stopped/
absent inventory is persisted before recovery; a failed CRI command is never
absence. Existing cgroups still pass the kernel identity and empty-target fence.
A mount-view difference is permitted only on this independently stopped recovery
path. A previous kernel boot requires the original pin directory to be absent,
not inspection of potentially reused numeric object IDs. Unknown retirement
durably seals delayed Ensure; retired IDs never reactivate.

## Historical signed provider protocol

The provider ID remains `agentsuite-guardd/v1`; transport version is `2`; provider protocol is `orka.enforcement-provider/v2`. Each request and response is one bounded JSON object followed by LF on a Unix `SOCK_STREAM` connection. Request, parameter, authorization, and context objects reject missing or unknown fields. The server authenticates the caller UID using `SO_PEERCRED`; the Orka client independently pins the server UID.

External operations are `DiscoverDescriptor`, `NegotiateCapabilities`, `Prepare`, `Activate`, `ReadBack`, `GetProof`, `Release`, `GetStatus`, `Reconcile`, and `Cleanup`. Unknown transport versions, operations, and fields fail closed. Authorization times are RFC3339Nano UTC strings and policy bytes are base64. `Reconcile` binds the attempt ID. `Cleanup` binds attempt, activation, and cleanup IDs so altered retries conflict after restart. It accepts released activations and active activations whose stored proof has expired; Guardd rejects cleanup of an active activation while that proof is still fresh. Exact policy bytes and their AgentSuite length-framed digest are retained.

Descriptors are Ed25519-signed and bind provider ID, endpoint identity, algorithm, key ID/key, epoch, lifetime, protocol versions, and capabilities. Orka validates the descriptor against operator-pinned trust before using its proof key. Descriptor, authorization, readback, and proof identities use the v2 tagged length-framed transcripts. Proofs bind the authorization digest, activation, workload, provider, audience, challenge, policy, independent readback, epoch, lifetime, and key.

## Neutral held-native filesystem boundary

This is the separate `serve-enforcement` service, not the historical provider
protocol above. Root peers use Unix `SOCK_SEQPACKET`, one JSON packet per
request/reply, and `execution-enforcement/v1`. No signing seed, gateway
credential, Orka journal, runtime launch operation, or implicit exemption is
involved.

Optional neutral configuration:

```json
{"socket":"/run/task-enforcer/provider.sock","state":"/var/lib/task-enforcer/provider.db","pins":"/sys/fs/bpf/task-enforcer","object":"/opt/task-enforcer/network.bpf.o","filesystemObject":"/opt/task-enforcer/filesystem.bpf.o"}
```

`object` remains required and unchanged. `filesystemObject` must be compiled
from `gadget/program.bpf.c` for the target kernel. The actual
`bpf_lsm_inode_rename` hook has four arguments plus BPF's trailing chained
return value. Do not add the flags argument from the distinct
`security_inode_rename` wrapper. Confirm hook arity against the target BTF.

Standalone filesystem policy bytes are the existing compiler's canonical UTF-8
JSON (sorted keys, no whitespace, sorted unique normalized absolute paths):

```json
{"denyWritePaths":["/run/orka-enforcement/fs-canary"],"requiredCapabilities":["filesystem/deny-write/v1"],"version":"agentsuite.policy/v1"}
```

The requirement has exactly `format`, `bytes`, `digest`, `capabilities`:
`format` is `agentsuite.policy/v1`; `bytes` is base64 of the canonical bytes;
`capabilities` is exactly `["filesystem/deny-write/v1"]`; `digest` is the
existing AgentSuite framed digest, **not** bare SHA-256 of JSON:

```python
from agentsuite_guardd.model import canonical, policy_digest
raw = canonical({"version": "agentsuite.policy/v1",
                 "denyWritePaths": ["/run/orka-enforcement/fs-canary"],
                 "requiredCapabilities": ["filesystem/deny-write/v1"]})
# requirement bytes = base64.b64encode(raw).decode(); digest = policy_digest(raw)
```

The request has exactly:

```json
{"version":"execution-enforcement/v1","method":"activate","operation":"runtime-owned-stable-operation","requirement":{"format":"agentsuite.policy/v1","bytes":"<base64>","digest":"sha256:<framed-digest>","capabilities":["filesystem/deny-write/v1"]},"target":{"boot":"<boot-id>","cgroup":{"dev":0,"ino":0,"mount_id":0,"cgroup_id":0},"pid":123,"start":"<proc-start>","netns":0,"generation":1}}
```

Target fields retain their existing runtime contract. `pid` is observational
metadata in the sender's PID namespace; only the received pidfd selects a
receiver-local process. Activation requires SCM_RIGHTS **in order**:
`cgroupfd, pidfd, netnsfd`. All protected canaries must already exist in the
held process's root, before activation, with final names and topology.
Assessment (`method="assess"`, empty operation, null target, no descriptors)
checks the compiler and configured backend only, never kernel readiness or
target support. Filesystem subtree/interface/unknown-kind activation refuses.
No combined-network fields/capabilities are accepted.

### Independent observer readback

While the challenge is held awaiting observer acknowledgement, a root observer
sends `method="lookup"` with the **identical original** operation, requirement
and target and one SCM_RIGHTS cgroupfd. For example, given the runtime's exact
binding request in `binding.json`:

```python
import array, json, os, socket
request = json.load(open("binding.json"))
request["method"] = "lookup"
fd = os.open("/sys/fs/cgroup/<exact-bound-cgroup>",
             os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(10)
        peer.connect("/run/task-enforcer/provider.sock")
        peer.sendmsg([json.dumps(request).encode()],
                     [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
        data, ancillary, flags, _ = peer.recvmsg(1048576)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise RuntimeError("truncated readback")
        reply = json.loads(data)
        assert reply["ok"] and reply["result"]["active"]
        print(json.dumps(reply["result"], sort_keys=True))
finally:
    os.close(fd)
```

The observer may open the cgroup through a different cgroupfs mount than the
runtime. Filesystem lookup still requires identical boot/device/inode/kernel
cgroup ID and a live cgroup-v2 directory FD; only the descriptor's mount-view
ID may differ. The stored association, including the original mount ID, must
remain byte-identical. Activation and retirement retain their existing checks.
The authenticated process's root and mount-namespace snapshot is independently
reverified and is not relaxed by this descriptor-view comparison.

The reply binds `operation`, `binding`, `requirement`, `target`; identity
hashes use the neutral service's canonical-JSON SHA-256 identity, distinct
from the policy's framed digest. `phase="ACTIVE"` alone is not evidence.
Filesystem `result.readback` is obtained by **new kernel readback** on each
successful lookup, compared with immutable durable ownership:

- `maps`: all three exact ABIs/IDs; both policy maps must be frozen;
- complete `guarded_targets` dump equals only the bound cgroup ID/generation;
- complete `guarded_paths` dump equals only captured `(generation, kernel
  dev_t, inode)` entries with the full ten-operation mask and reserved zero;
- `programs` and `links`: all 15 distinct IDs, exact program-to-link identity,
  exact LSM hook BTF identity and private-map ownership. Program names accept
  either bpftool's full BTF function name or the kernel's 15-byte object name;
  IDs, map ownership and hook checks remain mandatory in either case;
- `filesystem`: receiver-local PID/start, root and mount identity, paths,
  entries `[path,kernel_dev_t,inode,file_mode,ctime_ns]`, and generation.

Protected root/path identities are recaptured and compared before success.
Failure is explicit: it does not detach anything or turn ACTIVE SQLite state
into release authority. Restart does not reinstall or silently adopt changed
paths. The original root process must still be alive in the exact cgroup.

For an observer independent of the service's JSON response, pins live under
`<pins>/<sha256(operation UTF-8).hexdigest()>`. Root may additionally use
`bpftool -j map show/dump pinned <directory>/guarded_targets` and
`guarded_paths`, plus `bpftool -j prog show pinned <directory>/<name>-prog`
and `bpftool -j link show pinned <directory>/<name>-link`, cross-checking the
reported exact IDs and hook attachments. Userspace `st_dev` must be converted
to kernel dev_t with `(os.major(st_dev) << 20) | os.minor(st_dev)`.
Lookup returns no active success if a pin/map/link/hook/identity diverges.
Each verification freshly reads all kernel objects and protected identities.
Immutable hook BTF is dumped and indexed once per referenced BTF object within
that verification only; no authority or readback is cached across calls.

Retirement uses the same exact original association and one cgroupfd, after
runtime-owned stop. Three stable empty/populated-zero observations precede
any removal. Durable `EMPTY_CONFIRMED` cleanup retries may omit descriptors
after cgroup deletion; they confer no activation/lookup/release authority.
Retiring an unknown operation after the same empty-target fence durably
tombstones its association, preventing a delayed activation from recreating it.
Retirement also accepts the exact still-held cgroup FD after kernel-confirmed
removal: a removed cgroup cannot contain processes or children or be populated
again. Removed handles never authorize activation or active lookup. A lost
handle after daemon restart is not absence proof; cleanup then still needs a
previously persisted empty-target confirmation or independently verified
runtime-owned stop evidence in an adapter that supplies it.
Changed ownership refuses. Uncertain installs remain cleanup-only.
There is no audit mode and no filesystem-only network claim.
