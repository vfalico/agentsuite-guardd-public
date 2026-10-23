"""Complete two-gate readback tests; native packet evidence is separate."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from agentsuite_guardd.namespace_policy import NamespacePolicy


def plan(endpoints=()):
    return [x['add'] for x in NamespacePolicy.desired('op','tap0',endpoints)['nftables']]


def test_two_atomic_gates_no_broad_established_or_port_exemption():
    objects=plan([('10.0.0.1',443)])
    chains=[x['chain'] for x in objects if 'chain' in x]
    assert chains==[
        dict(family='netdev',table=NamespacePolicy.name('op'),name='boundary',type='filter',hook='ingress',dev='tap0',prio=-500,policy='drop'),
        dict(family='inet',table=NamespacePolicy.name('op'),name='boundary',type='filter',hook='prerouting',prio=-150,policy='accept')]
    rules=[x['rule'] for x in objects if 'rule' in x]
    assert len(rules)==5
    early=rules[1]['expr']
    assert early[0]['match']['right']=='tcp'
    assert early[1]['match']['left']['&'][1]==16383
    reply=rules[2]['expr']
    assert reply[0]['match']['right']=='tap0'
    assert reply[1]['match']['right']=='tcp'
    assert reply[2]['match']==dict(op='==',left={'ct':{'key':'direction'}},right='reply')
    assert reply[3]['match']==dict(op='==',left={'ct':{'key':'state'}},right='established')
    assert rules[3]['expr'][2]['match']['right']=='10.0.0.1'
    assert rules[3]['expr'][3]['match']['right']==443
    assert rules[-1]['expr']==[reply[0],{'drop':None}]
    assert len([x for x in rules if x['family']=='inet' and {'accept':None} in x['expr']])==2


def test_deny_all_still_has_only_tracked_reply_and_bound_drop():
    rules=[x['rule'] for x in plan() if 'rule' in x and x['rule']['family']=='inet']
    assert len(rules)==2
    assert {'match':dict(op='==',left={'ct':{'key':'direction'}},right='reply')} in rules[0]['expr']
    assert rules[-1]['expr'][-1]=={'drop':None}


def dumps(mutate=None):
    objects=deepcopy(plan([('10.0.0.1',443)]))
    objects[1]['chain'].pop('dev')
    if mutate:mutate(objects)
    return {family:{'nftables':[x for x in objects if next(iter(x.values()))['family']==family]} for family in ('netdev','inet')}


@pytest.mark.parametrize('mutation',[
    lambda xs:xs.pop(),
    lambda xs:xs[-3]['rule']['expr'].pop(2), # erase reply direction
    lambda xs:xs[5]['chain'].update(prio=0), # moved behind DNAT
    lambda xs:xs[5]['chain'].update(hook='forward'), # bypass local input
    lambda xs:xs[-1]['rule']['expr'][0]['match'].update(right='foreign'),
    lambda xs:xs.append({'rule':dict(family='inet',table=NamespacePolicy.name('op'),chain='boundary',expr=[{'accept':None}])}),
])
def test_readback_refuses_any_gate_or_direction_mutation(mutation):
    policy=NamespacePolicy();inventory=dumps(mutation)
    with patch.object(policy,'run',side_effect=lambda fd,args:inventory[args[2]]),patch('agentsuite_guardd.namespace_policy.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'type filter hook ingress device tap0 priority -500; policy drop;')):
        with pytest.raises(ValueError,match='complete namespace boundary readback mismatch'):
            policy.verify(7,'op','tap0',[('10.0.0.1',443)])


def test_exact_readback_and_atomic_pair_removal():
    policy=NamespacePolicy();inventory=dumps();calls=[]
    def run(fd,args,data=None):
        calls.append((args,data))
        if args[0]=='list' and args[1]=='table':return inventory[args[2]]
        return {'nftables':[]}
    with patch.object(policy,'run',side_effect=run),patch('agentsuite_guardd.namespace_policy.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'type filter hook ingress device tap0 priority -500; policy drop;')):
        policy.remove(7,'op','tap0',[('10.0.0.1',443)])
    assert calls[-2]==(['-f','-'],{'nftables':[{'delete':{'table':dict(family=f,name=policy.name('op'))}} for f in ('netdev','inet')]})
    assert calls[-1][0]==['list','tables']
