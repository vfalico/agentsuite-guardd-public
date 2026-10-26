from __future__ import annotations
import argparse, json, os, secrets, signal, sqlite3, sys
from .backend import BackendError, MemoryBackend, PersistentBackend
from .config import load_config, load_signing_seed
from .crypto import Signer
from .live_adapter import LinuxBPFAdapter, LiveAdapterError
from .provider import Provider
from .store import Store
from .transport import UnixServer


def build_provider(config_path):
    c = load_config(config_path)
    signer = Signer(load_signing_seed(c.key_file))
    store = Store(c.state)
    if c.backend == "conformance-memory":
        backend = MemoryBackend()
    elif c.backend == "linux-bpf":
        adapter = LinuxBPFAdapter(
            c.adapter_state,
            bpffs_root=c.bpffs_root,
            cgroup_root=c.cgroup_root,
            bpftool=c.bpftool,
        )
        backend = PersistentBackend(c.backend_state, adapter=adapter)
    else:
        raise ValueError("backend must be linux-bpf or conformance-memory")
    return c, Provider(store, backend, signer, endpoint_id=c.endpoint_id)


def main(argv=None):
    p = argparse.ArgumentParser(prog="agentsuite-guardd")
    p.add_argument("--config", default="/etc/agentsuite-guardd/config.json")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("descriptor")
    sub.add_parser("serve")
    sub.add_parser("serve-enforcement")
    sub.add_parser("serve-kubernetes-enforcement")
    sub.add_parser("serve-guest-enforcement")
    installation = sub.add_parser("reconcile-kubernetes-installation")
    installation.add_argument("--namespace", required=True)
    installation.add_argument("--installation", required=True)
    installation.add_argument("--disable-enrollment", action="store_true")
    c = sub.add_parser("compile")
    c.add_argument("policy")
    c.add_argument("--digest", required=True)
    c.add_argument("--target", required=True)
    a = p.parse_args(argv)
    try:
        if a.command == "reconcile-kubernetes-installation":
            from .kubernetes_install import reconcile
            print(json.dumps(reconcile(
                a.namespace, a.installation, disable_enrollment=a.disable_enrollment,
            ), sort_keys=True))
            return 0
        if a.command == "serve-kubernetes-enforcement":
            from .enforcement_server import serve_file
            serve_file(a.config)
            return 0
        if a.command == "serve-guest-enforcement":
            from .guest_stream import serve_file
            serve_file(a.config)
            return 0
        if a.command == "serve-enforcement":
            from .neutral_service import serve_file
            serve_file(a.config)
            return 0
        if a.command == "compile":
            from .policy import compile_policy

            data = open(a.policy, "rb").read()
            print(
                json.dumps(
                    compile_policy(data, a.digest, a.target).object(), sort_keys=True
                )
            )
            return 0
        config, provider = build_provider(a.config)
        if a.command == "descriptor":
            print(json.dumps(provider.descriptor(), sort_keys=True))
            return 0
        reconciliation = provider.reconcile_all()
        failed = {
            k: v for k, v in reconciliation.items() if v.get("state") == "quarantined"
        }
        if failed:
            details = "; ".join(
                f"{key}: {value.get('error', 'unknown reconciliation failure')}"
                for key, value in sorted(failed.items())
            )
            raise ValueError(
                "startup reconciliation failed: " + details
            )
        server = UnixServer(
            config.listen[7:], provider, config.allowed_uids, config.socket_mode
        )

        def stop(signum, frame):
            server.shutdown()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        server.serve_forever()
        return 0
    except (
        OSError,
        ValueError,
        PermissionError,
        sqlite3.Error,
        BackendError,
        LiveAdapterError,
    ) as e:
        print(f"agentsuite-guardd: configuration error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
