"""Guest transport/service cleanup regressions. Fake native backend, no kernel claim."""
from unittest.mock import patch
import pytest
from agentsuite_guardd import guest_stream
from agentsuite_guardd.neutral_service import Service
from test_neutral_service import Native, REQ, target


def req(method='activate', operation='original'):
    identity = target(1)
    identity = {k: identity[k] for k in ('boot', 'cgroup', 'generation')}
    identity['kind'] = 'cgroup-subtree/v1'
    return dict(version='execution-enforcement/v1', method=method,
                operation=operation, requirement=REQ, target=identity,
                locator='/sys/fs/cgroup/test-prepared')


def test_cleanup_checkpoint_survives_transport_target_deletion(tmp_path):
    service = Service(tmp_path/'state', tmp_path/'pins', Native())
    identity = {k: req()['target'][k] for k in ('boot', 'cgroup')}
    try:
        with patch.object(guest_stream, 'open_scope', return_value=9), \
             patch.object(guest_stream.os, 'close'), \
             patch('agentsuite_guardd.neutral_service.target_identity', return_value=identity), \
             patch('agentsuite_guardd.neutral_service.task_ids', return_value=[]), \
             patch('agentsuite_guardd.neutral_service.read_events', return_value={'populated': 0}):
            assert guest_stream.handle(service, req())['active']
            with patch.object(service, 'remove', side_effect=OSError('injected partial teardown')):
                with pytest.raises(OSError, match='partial teardown'):
                    guest_stream.handle(service, req('retire'))
            assert service.row('original')[2] == 'EMPTY_CONFIRMED'
        service.close()
        # Real new Store/process-equivalent object, not mutation of phase.
        service = Service(tmp_path/'state', tmp_path/'pins', Native())
        with patch.object(guest_stream, 'open_scope', side_effect=FileNotFoundError('deleted')):
            assert guest_stream.handle(service, req('retire'))['retired']
            assert guest_stream.handle(service, req('retire'))['retired']
            for method in ('activate', 'lookup', 'describe'):
                q = req(method)
                if method == 'describe':
                    q = {k: q[k] for k in ('version', 'method', 'locator')}
                    q['generation'] = 1
                with pytest.raises(FileNotFoundError):
                    guest_stream.handle(service, q)
            with pytest.raises(ValueError, match='exact cgroup handle'):
                guest_stream.handle(service, req('retire', 'unknown'))
            changed = req('retire')
            changed['target']['generation'] = 2
            with pytest.raises(ValueError, match='cannot change'):
                guest_stream.handle(service, changed)
    finally:
        service.close()


@pytest.mark.parametrize('phase', ['ACTIVE', 'ACTIVATING'])
def test_missing_locator_never_proves_active_target_empty(tmp_path, phase):
    service = Service(tmp_path/'state', tmp_path/'pins', Native())
    identity = {k: req()['target'][k] for k in ('boot', 'cgroup')}
    try:
        with patch('agentsuite_guardd.neutral_service.target_identity', return_value=identity):
            if phase == 'ACTIVATING':
                service.native.fail = True
                with pytest.raises(RuntimeError):
                    service.dispatch({k: v for k, v in req().items() if k != 'locator'}, [9])
            else:
                service.dispatch({k: v for k, v in req().items() if k != 'locator'}, [9])
        with patch.object(guest_stream, 'open_scope', side_effect=FileNotFoundError('deleted')):
            with pytest.raises(ValueError, match='exact cgroup handle'):
                guest_stream.handle(service, req('retire'))
        assert service.row('original')[2] == phase
    finally:
        service.close()
