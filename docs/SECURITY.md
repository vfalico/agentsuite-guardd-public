# Security model

The Ed25519 signing seed must be a regular root-owned file with no group/world permission bits. No environment or development fallback exists. Unix transport authenticates peers with `SO_PEERCRED`; signed descriptors additionally bind operator-pinned provider ID, endpoint ID, algorithm, key ID/key, minimum epoch, and freshness.

Activation success is not proof. The packaged `LinuxBPFAdapter` advertises `filesystem/deny-write/v1` only while two pinned maps and all fifteen pinned LSM links are independently queryable. A generation derived from activation identity and desired configuration namespaces each policy. Exact `(device,inode)` path entries are installed before the exact cgroup target entry, so a partial activation cannot enable an empty policy. Kernel readback verifies target generation, every policy value, every attached link, and every current path identity. Removal of any required object revokes capability advertisement or fails readback.

The policy covers listed roots and descendants existing at activation. Mutation hooks on protected parent directories deny creating, linking, renaming, or symlinking new entries beneath them; hooks on protected inodes deny writable opens, writes, truncation, metadata changes, unlink, and mount bypass. Exact cgroup targeting ensures unlisted paths and non-target cgroups are unaffected. Privileged positive, negative, bypass, restart, and cleanup tests exercise these boundaries.

Startup reconciles provider, backend, and kernel inventories. Missing desired/live attachments fail closed and live orphans are detached. Cleanup requires either a durable released state or an active activation whose stored proof has independently expired; an active proof that is still fresh cannot be cleaned. Cleanup disables the target before deleting policy entries. Rollback or cleanup ambiguity quarantines the backend. Exact altered retries conflict after restart.

## Neutral held-native filesystem scope

The `serve-enforcement` filesystem lane uses the existing ten-operation
filesystem compiler and fifteen filesystem LSM hooks, but not the legacy
global adapter, signing protocol, host-path resolver, or expiry-based cleanup.
It is a **protected existing inode/tree mutation ceiling**, not a full
filesystem allowlist, read-confidentiality policy, network restriction, or
general privileged-process sandbox.

Only an authenticated held-native process boundary is accepted. The three
transferred descriptors authenticate cgroup, process incarnation and network
namespace; the receiver-local pidfd process supplies the filesystem root and
mount namespace. Strict FD-relative traversal rejects symlinks in explicitly
selected path components, missing entries, special files, non-normal paths and
traversal-limit violations. Descendant symlinks are protected inodes; their
destinations are never followed or implicitly added. Protected
root/descendant identities are captured before attachment and checked again
after all links/maps are independently read back. Retained FDs prevent inode
reuse while the daemon lives; durable dev/inode/mode/ctime plus process/root/
mount identities reject changed recovery snapshots after restart.

The runtime/operator must keep the prepared process held until successful
activation, preserve the root process and mount topology during the challenge,
and prevent ungoverned principals from altering protected topology. Ordinary
runtime mounts must exist before activation. Exact-inode hooks do not track
future path replacements by an unrestricted external actor, protect reads,
or mediate every possible privileged mount/namespace/memory-mapping mechanism.
Do not treat this as assurance for arbitrary privileged workloads or inherited
writable memory mappings. Use an executable-but-not-writable operator-owned
parent to prevent the governed UID moving/replacing the canary root. External
same-UID unrestricted control mutations must finish and restore topology
**before** activation and baseline capture.

The kernel target map has exactly one cgroup entry, never an implicit exempt
process. Checks include absolute hierarchy levels 0 through 63, covering child
cgroups of qualified targets within those levels. Deeper target profiles are not
qualified by this claim. Each operation has independent maps/links; the policy
maps are frozen before any link attaches. The mutable ring buffer contains only
best-effort denial telemetry and is not policy authority. Complete map dumps,
private program map IDs, all hook BTF identities, links, and durable ownership
must agree for activation or lookup. Lookup returns fresh readback evidence,
not an ACTIVE database assertion. Failures retain existing restrictions.
Retirement requires runtime-owned stop plus the service's stable-empty fence;
partial-install cleanup journals the surviving exact IDs before unpinning and
requires their kernel absence. No live-infrastructure acceptance is implied by
unit tests or successful BPF compilation.

## Kubernetes container profile

The mTLS adapter resolves the complete containerd ID through an operator-trusted
CRI endpoint, verifies exact Kubernetes labels and the registered node UID,
and holds kernel descriptors outside the governed container. The whole target
cgroup and its qualified descendants are covered: no supervisor, worker, root
UID or child-process exemption is installed.

The supported target has private PID and mount namespaces, no `CAP_SYS_ADMIN`,
`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_MODULE` or `CAP_SYS_RAWIO`, and read-only
cgroup access. Validation checks both OCI configuration and **every actual
cgroup/cgroup2 mount** in the target process's mountinfo, including aliases.
A read-only `/sys/fs/cgroup` alone is insufficient when a writable host alias
is exposed elsewhere. The provider requires the complete host cgroup hierarchy
and namespace, and refuses targets at or beyond the bounded ancestor-search
depth. Arbitrary privileged containers are not qualified.

The runtime must hold workload launch until current verified evidence exists.
Only trusted bootstrap preparation may precede that point. Neither a running
Pod nor an RPC deadline authorizes workload release. Bindings protect physical
container incarnations across consuming Tasks/sessions; ending one consumer
does not authorize detachment from a retained live container. Restart does not
rebase policy or convert uncertain state to success. Kernel-boot, exact cgroup
and independent CRI stop evidence govern recovery and retirement as described
in the protocol.

The native Kubernetes qualification uses a newly owned lab Pod and real
kernel enforcement, authenticated RPC, populated-container re-verification and
stopped-target restart cleanup. This is backend/adapter evidence, not proof of
chart installation, Orka pre-launch gates, Kaimahi submission or real-model
end-user journeys.

## Combined network and filesystem policy

The optional v3 container backend adds the explicit IPv4 TCP/UDP endpoint
ceiling in [CONTAINER_POLICY.md](CONTAINER_POLICY.md) to the same immutable
filesystem target generation, object readback and stop-before-retirement
lifecycle. A filesystem-only requirement never acquires this network claim.
The object must be present in trusted configuration; there is no automatic
policy conversion or implicit connectivity grant.

Current-sender socket hooks cover inherited IPv4 sockets in addition to
cgroup connect/sendmsg and packet egress. Unix allowance is limited to unbound
stream socketpairs whose endpoints belong to the exact current cgroup.
Preexisting datagram/seqpacket pairs, bound/listener peers and received socket
descriptors are not allowed. Allowed inherited TCP/UDP endpoints remain usable.
Existing dual-stack TCP listeners may accept connections, but send-time
authorization admits only exact IPv4-mapped peers through the ordinary IPv4
endpoint map. Genuine IPv6 peers remain unable to send responses; accepting or
receiving a connection is not an IPv6 egress grant.
These restrictions are not an HTTP-host/TLS-identity filter or arbitrary
privileged-container sandbox.
