"""Deterministic contract tests; no native enforcement claims."""
import base64
import hashlib
import json
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
from agentsuite_guardd.neutral_service import Service, identity

RAW=json.dumps({'version':'agentsuite.policy/v2','network':{'egressAllow':[]},'requiredCapabilities':['network/egress-allow/v1']},sort_keys=True,separators=(',',':')).encode()
REQ={'format':'agentsuite.policy/v2','bytes':base64.b64encode(RAW).decode(),'digest':'sha256:'+hashlib.sha256(b'agentsuite-effective-policy\0v1\0'+struct.pack('>Q',len(RAW))+RAW).hexdigest(),'capabilities':['network/egress-allow/v1']}
def target(n):return dict(boot='test-boot',cgroup=dict(dev=1,ino=n),pid=200+n,start='1',netns=1,generation=1)
def request(method='activate',op='a',n=1):return dict(version='execution-enforcement/v1',method=method,operation=op,requirement=REQ,target=target(n))
class Native:
 PROGRAMS={}
 def __init__(self):self.installs=0;self.fail=False
 def install(self,*a):
  self.installs+=1
  if self.fail:raise RuntimeError('partial install')
  return dict(maps={},links={},programs={})
 def verify(self,*a):return dict(maps={},links={},programs={})
@pytest.fixture
def service(tmp_path):
 n=Native();s=Service(tmp_path/'state',tmp_path/'pins',n)
 with patch('agentsuite_guardd.neutral_service.held_target'),patch('agentsuite_guardd.neutral_service.target_identity',return_value=dict(boot='test-boot',cgroup=dict(dev=1,ino=1))),patch('agentsuite_guardd.neutral_service.task_ids',return_value=[]),patch('agentsuite_guardd.neutral_service.read_events',return_value=dict(populated=0)):
  yield s
 s.close()
def test_exact_retry_never_installs_twice(service):
 a=service.dispatch(request(),[1,2,3]);assert a['active']
 assert service.dispatch(request(),[1,2,3])==a
 assert service.native.installs==1
 for field in ['generation','netns','start']:
  q=request();q['target'][field]=2
  with pytest.raises(ValueError,match='cannot change'):service.dispatch(q,[1,2,3])
def test_same_target_never_duplicate_operation(service):
 service.dispatch(request(),[1,2,3])
 with pytest.raises(Exception,match='UNIQUE'):service.dispatch(request(op='b'),[1,2,3])
 assert service.native.installs==1
def test_partial_install_is_cleanup_only(service):
 service.native.fail=True
 with pytest.raises(RuntimeError):service.dispatch(request(),[1,2,3])
 assert service.row('a')[2]=='ACTIVATING'
 with pytest.raises(ValueError,match='cleanup-only'):service.dispatch(request(),[1,2,3])
 assert not service.dispatch(request('lookup'),[1])['active']
 assert service.dispatch(request('retire'),[1])['retired']
 assert service.row('a')[2]=='RETIRED'
def test_stable_empty_before_removal(service):
 service.dispatch(request(),[1,2,3])
 with patch('agentsuite_guardd.neutral_service.task_ids',return_value=[9]):
  with pytest.raises(ValueError,match='runtime-stopped'):service.dispatch(request('retire'),[1])
 assert service.row('a')[2]=='ACTIVE'
def test_cleanup_fault_checkpoint_survives_deleted_target(service):
 service.dispatch(request(),[1,2,3])
 with patch.object(service,'remove',side_effect=OSError('injected unlink')):
  with pytest.raises(OSError):service.dispatch(request('retire'),[1])
 assert service.row('a')[2]=='EMPTY_CONFIRMED'
 # No target authority is required or produced by this durable cleanup-only retry.
 with patch('agentsuite_guardd.neutral_service.target_identity',side_effect=OSError('deleted')):
  assert service.dispatch(request('retire'),[])['retired']
 assert not service.dispatch(request('lookup'),[1])['active']
def test_overlapping_bindings_retire_one_not_other(service):
 service.dispatch(request(),[1,2,3]);service.dispatch(request(op='b',n=2),[4,5,6])
 service.dispatch(request('retire'),[1]);assert service.row('b')[2]=='ACTIVE'
 assert service.native.installs==2
def test_process_store_lease(service):
 with pytest.raises(BlockingIOError):Service(service.state,service.pins,service.native)
def test_support_without_activation(service):
 q=request('assess',op='');q['target']=None
 assert service.dispatch(q,[])==dict(supported=True)
 assert service.native.installs==0
 q['requirement']=dict(REQ,format='non-suite-test/v1');assert not service.dispatch(q,[])['supported']
 q=request();q['requirement']=dict(REQ,bytes='malformed')
 with pytest.raises(ValueError):service.dispatch(q,[1,2,3])
 assert service.native.installs==0


def interface_request(method='retire'):
 q=request(method)
 q['target']=dict(kind='network-interface/v1',boot='test-boot',cgroup=dict(dev=1,ino=1),netns=dict(dev=2,ino=3,locator='/run/netns/test'),interface=dict(index=4,name='tap0',address='00:00:00:00:00:01'),generation=1)
 q['requirement']=dict(REQ,digest='sha256:'+'0'*64)
 return q

def test_rejected_interface_activation_can_retire_only_verified_absence(service):
 q=interface_request()
 with patch.object(service,'interface_target'),patch.object(service.namespace,'run',return_value={'nftables':[]}):
  assert service.dispatch(q,[1,2])['retired']
  assert service.row('a')[2]=='RETIRED'
  assert service.dispatch(q,[])['retired']
  q['method']='activate'
  with pytest.raises(ValueError):service.dispatch(q,[1,2])
  q['method']='retire';q['target']['generation']=2
  with pytest.raises(ValueError,match='cannot change'):service.dispatch(q,[])
 assert service.native.installs==0

@pytest.mark.parametrize('failure',['live','residue','inet-residue','inventory','handle'])
def test_unknown_interface_retirement_never_guesses(service,failure):
 q=interface_request();tables={'nftables':[]}
 if failure=='residue':tables={'nftables':[{'table':{'family':'netdev','name':service.namespace.name('a')}}]}
 if failure=='inet-residue':tables={'nftables':[{'table':{'family':'inet','name':service.namespace.name('a')}}]}
 if failure=='inventory':tables={}
 with patch.object(service,'interface_target',side_effect=ValueError('bad handle') if failure=='handle' else None),patch.object(service.namespace,'run',return_value=tables),patch('agentsuite_guardd.neutral_service.task_ids',return_value=[9] if failure=='live' else []):
  with pytest.raises(ValueError):service.dispatch(q,[1,2])
 assert service.row('a') is None


def test_retired_kernel_identity_does_not_reserve_reused_inode(service):
 service.dispatch(request(),[1,2,3])
 service.dispatch(request('retire'),[1])
 assert service.row('a')[1]=='retired:a'
 assert service.dispatch(request(op='b'),[1,2,3])['active']
 with pytest.raises(ValueError,match='cleanup-only'):service.dispatch(request(),[1,2,3])
 assert service.native.installs==2

def test_absence_tombstone_does_not_collide_with_prior_kernel_identity(service):
 q=interface_request()
 # A prior retired attempt may have observed the very same recycled handles.
 blob=json.dumps(dict(requirement=q['requirement'],target=q['target']),sort_keys=True,separators=(',',':')).encode()
 key=identity(dict(boot=q['target']['boot'],netns={k:q['target']['netns'][k] for k in ['dev','ino']},interface=q['target']['interface']))
 with service.db:service.db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?)',('prior',blob,key,'RETIRED',None,'netdev:prior'))
 with patch.object(service,'interface_target'),patch.object(service.namespace,'run',return_value={'nftables':[]}):
  assert service.dispatch(q,[1,2])['retired']
 assert service.row('a')[1]=='retired:a'


def test_interface_partial_boundary_never_activates_or_releases(service):
 q=interface_request('activate');q['requirement']=REQ
 with patch.object(service,'interface_target') as target_check,patch.object(service.namespace,'install') as install:
  with pytest.raises(ValueError,match='complete guest network ceiling'):
   service.dispatch(q,[1,2])
  assert service.row('a') is None
  target_check.assert_not_called();install.assert_not_called()
 # Preserve a historical active binding and its restrictions; lookup must not
 # let retry/restart turn old partial protection into release authority.
 blob=json.dumps(dict(requirement=q['requirement'],target=q['target']),sort_keys=True,separators=(',',':')).encode()
 with service.db:
  service.db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?)',('a',blob,'prior-interface','ACTIVE',None,'netdev:prior'))
 with patch.object(service,'interface_target'),patch.object(service.namespace,'verify'),patch.object(service.namespace,'remove') as remove:
  q['method']='lookup';reply=service.dispatch(q,[1,2])
  assert not reply['active'] and reply['phase']=='ACTIVE'
  assert service.row('a')[2]=='ACTIVE'
  q['method']='activate'
  with pytest.raises(ValueError,match='complete guest network ceiling'):
   service.dispatch(q,[1,2])
  assert service.row('a')[2]=='ACTIVE';remove.assert_not_called()
 # Exact cleanup still requires the existing runtime-stopped empty fence.
 q['method']='retire'
 with patch.object(service,'interface_target'),patch.object(service.namespace,'run',return_value={'nftables':[]}):
  assert service.dispatch(q,[1,2])['retired']
 assert service.row('a')[2]=='RETIRED'
