# Provider protocol

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
  exact LSM hook BTF identity and private-map ownership;
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

Retirement uses the same exact original association and one cgroupfd, after
runtime-owned stop. Three stable empty/populated-zero observations precede
any removal. Durable `EMPTY_CONFIRMED` cleanup retries may omit descriptors
after cgroup deletion; they confer no activation/lookup/release authority.
Unknown or changed ownership refuses. Uncertain installs remain cleanup-only.
There is no audit mode and no filesystem-only network claim.
