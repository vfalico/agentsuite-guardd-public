"""Diagnostic against final changed Guardd source paths; fake namespace only.

Run with PYTHONPATH pointing to reassembled Guardd src and its tests. This is
NOT a native kernel test and does NOT modify the delivered production patches.
"""
from unittest.mock import patch
import pytest
from test_neutral_service import service, interface_request, REQ


@pytest.mark.parametrize('inventory',[{}, {'nftables':None}, {'nftables':[None]}, {'nftables':[{}]}, {'nftables':[{'table':{}}]}, {'nftables':[{'chain':{}}]}])
@pytest.mark.parametrize('phase,handles', [('ACTIVE',[1,2]),('EMPTY_CONFIRMED',[])])
def test_unknown_inventory_cannot_prove_exact_retirement(service,phase,handles,inventory):
    q=interface_request('retire')
    q['requirement']=REQ
    from agentsuite_guardd.neutral_service import canonical
    with service.db:
        service.db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?)',
            ('a',canonical(dict(requirement=q['requirement'],target=q['target'])),
             'prior-exact-target',phase,b'{}','netdev:prior'))
    with patch.object(service,'interface_target'), \
         patch.object(service.namespace,'run',return_value=inventory), \
         patch('agentsuite_guardd.neutral_service.os.open',return_value=77), \
         patch('agentsuite_guardd.neutral_service.os.fstat') as stat, \
         patch('agentsuite_guardd.neutral_service.os.close'):
        stat.return_value.st_dev=2
        stat.return_value.st_ino=3
        with pytest.raises((ValueError,TypeError),match='inventory|malformed|unknown'):
            service.dispatch(q,handles)
    assert service.row('a')[2]!='RETIRED'


def test_unknown_post_delete_inventory_cannot_prove_absence(service):
    from agentsuite_guardd.namespace_policy import NamespacePolicy
    policy=NamespacePolicy()
    with patch.object(policy,'verify',return_value={}), \
         patch.object(policy,'run',side_effect=[{},{}]):
        with pytest.raises((ValueError,TypeError),match='inventory|malformed|unknown'):
            policy.remove(1,'operation','tap0',())


@pytest.mark.parametrize('inventory', [
    {'nftables':[]},
    {'nftables':[{'metainfo':{'version':'test'}}]},
    {'nftables':[{'table':{'family':'inet','name':'unrelated','handle':42}}]},
])
def test_valid_unrelated_inventory_can_prove_absence(service,inventory):
    from agentsuite_guardd.neutral_service import canonical
    q=interface_request('retire');q['requirement']=REQ
    with service.db:
        service.db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?)',
            ('a',canonical(dict(requirement=q['requirement'],target=q['target'])),
             'prior-exact-target','ACTIVE',b'{}','netdev:prior'))
    with patch.object(service,'interface_target'),patch.object(service.namespace,'run',return_value=inventory):
        assert service.dispatch(q,[1,2])['retired']
    assert service.row('a')[2]=='RETIRED'


def test_bad_post_delete_inventory_keeps_retry_owner(service):
    from agentsuite_guardd.neutral_service import canonical
    q=interface_request('retire');q['requirement']=REQ
    with service.db:
        service.db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?)',
            ('a',canonical(dict(requirement=q['requirement'],target=q['target'])),
             'prior-exact-target','ACTIVE',b'{}','netdev:prior'))
    table={'table':{'family':'netdev','name':service.namespace.name('a')}}
    with patch.object(service,'interface_target'),patch.object(service.namespace,'verify',return_value={}), \
         patch.object(service.namespace,'run',side_effect=[{'nftables':[table]}, {}, {}]):
        with pytest.raises(ValueError,match='inventory'):
            service.dispatch(q,[1,2])
    assert service.row('a')[2]=='EMPTY_CONFIRMED'
    with patch.object(service,'interface_target'),patch.object(service.namespace,'run',return_value={'nftables':[]}):
        assert service.dispatch(q,[1,2])['retired']
    assert service.row('a')[2]=='RETIRED'


@pytest.mark.parametrize('abrupt_exit',[False,True])
def test_inventory_fault_survives_fresh_service_process(tmp_path,abrupt_exit):
    """Real SQLite/process restart, explicitly mocked namespace observations."""
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys
    q=interface_request('retire');q['requirement']=REQ
    request_path=tmp_path/'request.json';request_path.write_text(json.dumps(q))
    child=r'''
import json,sys,os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from agentsuite_guardd.neutral_service import Service,canonical
root=Path(sys.argv[1]);phase=sys.argv[2];q=json.loads((root/'request.json').read_text())
s=Service(root/'state.db',root/'pins',object())
try:
 if phase=='initial':
  with s.db:
   s.db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?)',('a',canonical(dict(requirement=q['requirement'],target=q['target'])),'prior-exact-target','ACTIVE',b'{}','netdev:prior'))
  with patch.object(s,'interface_target'),patch.object(s.namespace,'run',return_value={}),patch('agentsuite_guardd.neutral_service.task_ids',return_value=[]),patch('agentsuite_guardd.neutral_service.read_events',return_value={'populated':0}):
   try:s.dispatch(q,[1,2])
   except ValueError as err:assert 'inventory' in str(err),str(err)
   else:raise AssertionError('malformed inventory accepted')
  assert s.row('a')[2]=='EMPTY_CONFIRMED'
  if os.environ.get('TEST_ABRUPT_OWNER_EXIT')=='1':
   print(phase,'PASS',flush=True);os._exit(0)
 elif phase=='replacement':
  assert s.row('a')[2]=='EMPTY_CONFIRMED'
  with patch('agentsuite_guardd.neutral_service.os.open',return_value=77),patch('agentsuite_guardd.neutral_service.os.close'),patch('agentsuite_guardd.neutral_service.os.fstat',return_value=SimpleNamespace(st_dev=2,st_ino=999)),patch.object(s.namespace,'run',side_effect=AssertionError('replacement must not be inspected or deleted')):
   try:s.dispatch(q,[])
   except ValueError as err:assert 'identity changed' in str(err),str(err)
   else:raise AssertionError('replacement accepted')
  assert s.row('a')[2]=='EMPTY_CONFIRMED'
 elif phase=='recover':
  assert s.row('a')[2]=='EMPTY_CONFIRMED'
  with patch('agentsuite_guardd.neutral_service.os.open',return_value=77),patch('agentsuite_guardd.neutral_service.os.close'),patch('agentsuite_guardd.neutral_service.os.fstat',return_value=SimpleNamespace(st_dev=2,st_ino=3)),patch.object(s.namespace,'run',return_value={'nftables':[]}):
   assert s.dispatch(q,[])['retired']
  assert s.row('a')[2]=='RETIRED'
  if os.environ.get('TEST_ABRUPT_OWNER_EXIT')=='1':
   print(phase,'PASS',flush=True);os._exit(0)
 elif phase=='retry':
  assert s.row('a')[2]=='RETIRED'
  with patch('agentsuite_guardd.neutral_service.os.open',return_value=77),patch('agentsuite_guardd.neutral_service.os.close'),patch('agentsuite_guardd.neutral_service.os.fstat',return_value=SimpleNamespace(st_dev=2,st_ino=3)),patch.object(s.namespace,'run',return_value={'nftables':[]}):
   assert s.dispatch(q,[])['retired']
  assert s.row('a')[2]=='RETIRED'
 else:raise AssertionError('unknown phase')
 print(phase,'PASS')
finally:s.close()
'''
    for phase in ['initial','replacement','recover','retry']:
        result=subprocess.run([sys.executable,'-c',child,str(tmp_path),phase],
            cwd=Path(__file__).resolve().parents[1],env=dict(os.environ,TEST_ABRUPT_OWNER_EXIT='1' if abrupt_exit else '0'),
            text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        assert result.returncode==0,(phase,result.stdout,result.stderr)
        assert phase+' PASS' in result.stdout
