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
mount namespace. Strict FD-relative traversal rejects every symlink, missing
entry, special file, non-normal path and traversal-limit violation. Protected
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

The kernel target map has exactly one cgroup entry, never a subtree or an
implicit exempt process. Each operation has independent maps/links; the policy
maps are frozen before any link attaches. The mutable ring buffer contains only
best-effort denial telemetry and is not policy authority. Complete map dumps,
private program map IDs, all hook BTF identities, links, and durable ownership
must agree for activation or lookup. Lookup returns fresh readback evidence,
not an ACTIVE database assertion. Failures retain existing restrictions.
Retirement requires runtime-owned stop plus the service's stable-empty fence;
partial-install cleanup journals the surviving exact IDs before unpinning and
requires their kernel absence. No live-infrastructure acceptance is implied by
unit tests or successful BPF compilation.
