# AgentSuite Guardd

AgentSuite Guardd includes a runtime-neutral whole-requirement network enforcement service and a retained compatibility implementation of the historical Orka enforcement-provider protocol. It validates exact canonical AgentSuite policy bytes, negotiates capabilities fail closed, performs activation plus independent readback, signs authenticated descriptors and proofs, and exposes all lifecycle operations over a versioned Unix socket.

## Build and test

```sh
PYTHONPATH=src python3 -m pytest
(cd adapter && go test -race ./...)
python3 -m build
```

The source tree or sdist is the deployable service artifact;
`packaging/install.sh` installs the Python application into a dedicated
`/opt/agentsuite-guardd/venv` environment plus its host BPF and systemd payload;
it never writes into the distribution-managed Python environment. The wheel
intentionally contains only the Python library and CLI. The packaged service
reads `/etc/agentsuite-guardd/config.json`, requires a root-owned mode-0600
Ed25519 seed, restores SQLite state, reconciles live attachment records,
authenticates Unix peers with `SO_PEERCRED`, and remains active at
`/run/agentsuite-guardd/provider.sock`. There is no signing-key fallback.

`MemoryBackend` and `backend: conformance-memory` are explicit test-only modes. The packaged `linux-bpf` backend uses `LinuxBPFAdapter`, which advertises `filesystem/deny-write/v1` only while both pinned kernel maps and all fifteen attached LSM links are independently observable. It compiles each deny path into exact `(generation, device, inode)` entries, enables the exact cgroup target only after all policy entries exist, and reads every map entry and current path identity back from kernel state. Startup reconciles persisted provider, backend, and live-map inventories; detach removes the target first, then policy entries. If any link, map, path identity, or inventory is absent or divergent, negotiation/readback fails closed.

## Local service smoke test

```sh
install -d -m 0700 /tmp/guardd-smoke
head -c 32 /dev/urandom > /tmp/guardd-smoke/key
chmod 0600 /tmp/guardd-smoke/key
# Create a config using backend "conformance-memory" and paths under /tmp/guardd-smoke.
PYTHONPATH=src python3 -m agentsuite_guardd.cli --config /tmp/guardd-smoke/config.json serve
```

Runtime roots are `/etc/agentsuite-guardd`, `/run/agentsuite-guardd`, and `/var/lib/agentsuite-guardd`. No remote service or registry is required to build this source handoff.

## Runtime-neutral network service (experimental)

`agentsuite-guardd --config /absolute/private/network.json serve-enforcement`
runs the `execution-enforcement/v1` Unix `SOCK_SEQPACKET` service implemented
in `neutral_service.py`. This is the network lane consumed by the coupled
runtime patchsets. The legacy `serve` command, signing-seed configuration,
Go adapter and filesystem systemd units above are a separate compatibility
lane; they do not start or configure the neutral service.

The neutral service configuration has exactly these four absolute paths:

```json
{"socket":"/run/task-enforcer/provider.sock","state":"/var/lib/task-enforcer/provider.db","pins":"/sys/fs/bpf/task-enforcer","object":"/opt/task-enforcer/network.bpf.o"}
```

Prepare dedicated root-owned directories with no untrusted write access.
Configuration must be a root-owned regular file with no group/other write
permission; socket access additionally requires a root `SO_PEERCRED` peer.
One exclusive database lease serializes daemon ownership. After an abrupt
crash startup may replace only a root-owned mode-0600 Unix socket in a
root-owned protected parent, after a real connect proves ECONNREFUSED and
its inode is rechecked. Live, foreign, symlink or uncertain addresses refuse
restart. Shutdown unlinks only the exact socket inode it bound.
Do not run this example on a production host without separate qualification.

Build `gadget/network.bpf.c` with a BTF-derived `vmlinux.h` and libbpf headers
for the target kernel; for example on x86-64:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /private/build/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/private/build -I/usr/include \
  -c gadget/network.bpf.c -o /private/build/network.bpf.o
```

Runtime prerequisites include cgroup v2, bpffs, BPF LSM, libbpf.so.1,
`bpftool`, and sufficient root capabilities. The interface backend additionally
uses nftables netdev ingress and inet pre-DNAT prerouting, `/usr/sbin/nft` and `/usr/bin/nsenter`.
The network object is source in the sdist; wheels contain the Python service,
not a kernel-specific precompiled object. The legacy installer does not install
this neutral lane. Keep the object, private configuration, state and socket
under task/operator-owned paths; building does not enable any service.

Each request supplies one complete immutable requirement: Suite effective
network-v2 bytes, framed digest and exact capability list. Unsupported policy
fields, capabilities and endpoint forms refuse; no partial-policy composition,
DNS exception, proxy allowance or inferred endpoint is added. Empty allow means
no permitted IP egress. Two generic target boundaries are supported:

- A stopped process with exact cgroup, pidfd and network-namespace handles;
  the kernel backend attaches and independently reads frozen maps and links.
- A non-running virtual workload's host network interface, with exact cgroup,
  namespace, interface and generation identity; one atomic nftables transaction
  installs two mandatory gates. Netdev ingress rejects fragments, UDP and IPv6;
  inet prerouting at priority -150 (after conntrack, before DNAT) admits only
  exact policy IPv4/TCP endpoints or established REPLY-direction TCP traffic
  to a host-initiated connection. There is no broad established/original, port,
  model, DNS or proxy exception. ARP is neighbour discovery, not IP traffic.
  Complete independent readback and atomic retirement cover both tables;
  either table as residue prevents unknown-operation cleanup acceptance.

The runtime owns target preparation, release, stop, restart and recovery.
Guardd neither launches workloads nor interprets runtime task/session/journal
schemas. Activation and lookup are exact-operation and exact-target checks;
uncertain states are cleanup-only. Runtime-confirmed stable emptiness precedes
retirement, and immutable tombstones do not indefinitely reserve reused kernel
identities. Lost replies retain ownership for exact reconciliation. These
semantics are not a claim that all public runtime integrations are qualified.

Current tests include unit/protocol tests with explicit fake backends, plus
separately captured task-owned native process and microVM boundary trials.
A passing fake-backend test is not native enforcement acceptance. Run the
complete Python tests and packaging checks separately from privileged trials.

The process boundary also checks the current sender at `socket_sendmsg`:
otherwise sockets created in an ungoverned parent retain their original cgroup
and bypass cgroup-skb checks after inheritance. Inherited IPv4/TCP sends must
match the complete endpoint map. Foreign AF_UNIX sockets are refused as local
broker delegation; internal same-boundary socketpairs remain usable. SCM_RIGHTS
socket reception is refused separately by `file_receive`. These are enforcement
checks, not a claim that arbitrary privileged local brokers are in the profile.

`tests/native/descriptor_probe.py /absolute/fresh/output /absolute/network.bpf.o`
is a privileged opt-in discriminator (set `PYTHONPATH=src`). It compares real
unrestricted controls with governed inherited allowed/forbidden TCP sockets,
foreign connected AF_UNIX delegation, SCM_RIGHTS reception, fresh TCP and
internal socketpairs, and independently reads receiver arrivals. It is not
collected by pytest and is not public-runtime acceptance.


### Interface-only boundary is unsupported for a complete guest ceiling

A native tool in the qualified VM exchanged traffic with an unlisted guest
loopback endpoint without crossing the host TAP. Therefore `network-interface/v1`
activation now refuses the whole requirement, including exact retries. Advisory
policy assessment is not target support or permission to release. Lookup of old
interface records returns `active: false` without deleting restrictions or changing
the durable phase. Runtime owners must stop compute and use exact retirement;
they must not drop restrictions on a running old target. The retained interface
implementation is cleanup/diagnostic compatibility, **not** complete-policy
support. Kagent and AgentSessions guest positive observations from before this
correction do not qualify the corrected tree. A guest-visible complete boundary
is still required for those lanes; no policy-free fallback is authorized.
