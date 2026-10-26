# Combined container policy

`agentsuite.policy/v3` requires filesystem and network enforcement together on
one physical container. Its opaque policy bytes are canonical JSON. The policy's
ordered `requiredCapabilities` must exactly match the request:

```json
{"denyWritePaths":["/protected"],"network":{"egressAllow":[{"address":"10.0.0.2","port":443,"protocol":"TCP"},{"address":"10.0.0.53","port":53,"protocol":"UDP"}]},"requiredCapabilities":["filesystem/deny-write/v1","network/egress-allow/v1"],"version":"agentsuite.policy/v3"}
```

The paths must exist before admission. Filesystem snapshots and mutation denial
have the same bounded held-root semantics as v1. This does not imply protection
of a repository that is not explicitly included.

Protection follows the existing inode identities captured before binding, within
the governed cgroup and its descendants. Existing descendant symlinks are
protected objects, but their external destinations are not followed or implicitly
protected. A policy root cannot traverse a symlink. Other cgroups are not made
read-only: privileged external modification invalidates the held-tree proof
rather than extending this policy to every writer. Do not add external fixtures
to a bound tree and treat them as part of its original snapshot.

Network rules allow literal unicast IPv4 destinations and TCP or UDP. A port is
an integer from 1 through 65535 or the explicit string `"*"` for all ports at
that address and protocol. Empty rules deny all IP egress. IPv6, raw/packet
sockets, other protocols, IP fragmentation and foreign Unix-socket delegation
are unsupported and denied. Internal same-cgroup Unix stream socketpairs remain
usable. Received socket descriptors are denied. An inherited TCP socket does
not bypass the current-sender endpoint check; ownership of such a socket alone
does not prohibit an otherwise explicitly allowed peer. Existing dual-stack TCP
listeners may accept IPv4-mapped peers; replies normalize only exact
`::ffff:a.b.c.d` peers to the same IPv4 address/port rules. This does not allow
actual IPv6 egress. Accept alone is not peer authorization: replies to actual
IPv6 peers are denied even when that connection predates activation.

There are no automatic DNS, Kubernetes, model, telemetry, control or reply grants.
Before submitting, the caller must materialize the actual required tuples into
the complete policy. Permit DNS resolver UDP/TCP port 53 explicitly when needed;
DNS does not authorize the resulting addresses. Service/NAT paths must include
both the original socket destination and the packet destination observed at the
egress hook. Inbound TCP is permitted, but every reply still requires an allowed
destination; a controller with ephemeral client ports can require an explicit
all-ports rule for its IP. This is an address/transport ceiling, not HTTP host,
URL, TLS-identity or application-direction authorization. A local proxy's allowed
address authorizes that proxy, not an independently enforced upstream hostname.
Addresses cannot be changed in place. A changed complete policy selects a new
binding/container through the runtime's ordinary admission rules.

The provider loads one combined object, freezes its complete maps and verifies
every link, hook, program/map dependency and exact map entry before returning
`ENFORCED`. Filesystem and network share the exact cgroup/generation. A partial
install is never admitted and is cleanup-only; surviving controls are retained
until positive physical-stop proof, then all owned objects must disappear.
An RPC timeout is uncertainty, not expiration or permission to weaken controls.

Kubernetes providers configure `containerObject` with the image's
`/opt/guardd/container.bpf.o`. Existing v1/v2 formats are not silently upgraded.
Build or unit-test success is not native kernel or end-user qualification.

A CRI Created container with verified exact Kubernetes ownership is Pending,
even when optional verbose runtime information is absent. It is not a live
physical target or an enforcement receipt. Running containers still require
complete PID and OCI isolation information before enforcement can proceed.
