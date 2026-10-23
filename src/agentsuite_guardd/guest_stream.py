"""Neutral host-authenticated guest transport for the ordinary enforcement service.

AF_VSOCK host CID is supplied by the guest kernel, not request bytes. The
runtime owns the VMM's protected hybrid socket; workload CID connections are
refused. No workload release, target creation, runtime schemas or guest exec.
"""
from __future__ import annotations
import json
import logging
import os
from pathlib import Path
import socket
import stat
import struct

from .native_network import Native
from .neutral_service import MAX_FRAME, VERSION, Service, canonical, exact, target_identity


def open_scope(locator):
    """Resolve an explicitly selected existing cgroup beneath the kernel mount."""
    if type(locator) is not str or not locator.startswith('/sys/fs/cgroup/'):
        raise ValueError('absolute cgroup-v2 locator required')
    parts = locator[len('/sys/fs/cgroup/'):].split('/')
    if any(p in {'', '.', '..'} for p in parts):
        raise ValueError('invalid cgroup locator')
    fd = os.open('/sys/fs/cgroup', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        st = os.fstat(fd)
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('runtime-owned protected cgroup required')
        # target_identity performs fstatfs validation, not pathname trust.
        target_identity(fd)
        return fd
    except Exception:  # AUDITED: BROAD — descriptor ownership must not leak on refusal
        os.close(fd)
        raise


def handle(service, request):
    if type(request) is not dict or request.get('version') != VERSION:
        raise ValueError('unsupported execution protocol')
    if request.get('method') == 'describe':
        exact(request, {'version', 'method', 'locator', 'generation'})
        generation = request['generation']
        if type(generation) is not int or generation < 1:
            raise ValueError('positive generation required')
        fd = open_scope(request['locator'])
        try:
            target = dict(target_identity(fd), kind='cgroup-subtree/v1', generation=generation)
            return dict(target=target)
        finally:
            os.close(fd)
    exact(request, {'version', 'method', 'operation', 'requirement', 'target', 'locator'})
    if request['target'].get('kind') != 'cgroup-subtree/v1':
        raise ValueError('guest stream needs exact cgroup subtree scope')
    message = {k: v for k, v in request.items() if k != 'locator'}
    try:
        fd = open_scope(request['locator'])
    except FileNotFoundError:
        # Only the service's durable EMPTY_CONFIRMED/RETIRED checkpoint can
        # authorize cleanup without a live target. Unknown/ACTIVE/ACTIVATING
        # records still refuse: a missing locator never proves emptiness.
        if request['method'] != 'retire':
            raise
        return service.dispatch(message, [])
    try:
        return service.dispatch(message, [fd])
    finally:
        os.close(fd)


def read_exact(conn, size):
    chunks = []
    while size:
        data = conn.recv(size)
        if not data:
            raise EOFError('incomplete enforcement frame')
        chunks.append(data)
        size -= len(data)
    return b''.join(chunks)


def notify_ready():
    """Advertise listener readiness only to an explicitly configured supervisor.

    Notification is startup-only, not exact-binding or activation authority.
    A configured delivery failure is fatal: never claim readiness on failure.
    """
    address = os.environ.get('NOTIFY_SOCKET')
    if address is None:
        return
    if not address or address[0] not in {'/', '@'}:
        raise ValueError('invalid readiness notification socket')
    if address.startswith('@'):
        address = '\0' + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
        notifier.connect(address)
        if notifier.send(b'READY=1') != len(b'READY=1'):
            raise OSError('incomplete readiness notification')


def serve_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        st = os.fstat(stream.fileno())
        if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISREG(st.st_mode):
            raise ValueError('root-owned protected config required')
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('oversized configuration')
    config = json.loads(raw)
    exact(config, {'port', 'state', 'pins', 'object'})
    if type(config['port']) is not int or not 1024 < config['port'] < 2**32:
        raise ValueError('explicit nonreserved vsock port required')
    for key in ('state', 'pins', 'object'):
        if type(config[key]) is not str or not Path(config[key]).is_absolute():
            raise ValueError('absolute trusted configuration required')
    service = Service(config['state'], config['pins'], Native(config['object']))
    try:
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as sock:
            sock.bind((socket.VMADDR_CID_ANY, config['port']))
            sock.listen(32)
            notify_ready()
            while True:
                conn, peer = sock.accept()
                with conn:
                    conn.settimeout(15)
                    logging.getLogger(__name__).warning("guest enforcement peer=%r", peer)
                    try:
                        if peer[0] != socket.VMADDR_CID_HOST:
                            raise PermissionError('only the owning host may bind guest scopes')
                        length = struct.unpack('>I', read_exact(conn, 4))[0]
                        if not 0 < length <= MAX_FRAME:
                            raise ValueError('frame bounds exceeded')
                        request = json.loads(read_exact(conn, length))
                        reply = dict(version=VERSION, ok=True, result=handle(service, request))
                    except Exception as error:  # AUDITED: BROAD — transport refusals never release workload
                        logging.getLogger(__name__).warning("guest enforcement refusal", exc_info=True)
                        reply = dict(version=VERSION, ok=False, error=str(error))
                    data = canonical(reply)
                    try:
                        conn.sendall(struct.pack('>I', len(data)) + data)
                    except OSError:
                        logging.getLogger(__name__).warning('guest enforcement reply lost', exc_info=True)
    finally:
        service.close()
