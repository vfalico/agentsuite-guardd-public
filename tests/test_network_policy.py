import hashlib
import json
import struct

import pytest
from agentsuite_guardd.network_policy import CAPABILITY, compile_network


def encoded(rules):
    return json.dumps({'version':'agentsuite.policy/v2','network':{'egressAllow':rules},'requiredCapabilities':[CAPABILITY]},sort_keys=True,separators=(',',':')).encode()


def digest(raw):
    return 'sha256:'+hashlib.sha256(b'agentsuite-effective-policy\0v1\0'+struct.pack('>Q',len(raw))+raw).hexdigest()


def rule(address='127.0.0.1',port=18081,protocol='TCP'):
    return dict(address=address,port=port,protocol=protocol)


@pytest.mark.parametrize('rules',[[],[rule()],[rule('10.0.0.1',port) for port in range(1,4097)]])
def test_full_capacity_and_intentional_deny_all(rules):
    raw=encoded(rules);p=compile_network(raw,digest(raw),[CAPABILITY])
    assert p.policy_bytes==raw
    assert p.endpoints==tuple((r['address'],r['port']) for r in rules)


@pytest.mark.parametrize('rules',[[rule('localhost')],[rule('::1')],[rule(protocol='UDP')],[rule(port=True)],[rule(port=0)],[rule(),rule()],[rule('0.0.0.0')],[rule('224.0.0.1')],[dict(rule(),extra=1)]])
def test_unsupported_rules_refuse_wholly(rules):
    raw=encoded(rules)
    with pytest.raises(ValueError):compile_network(raw,digest(raw),[CAPABILITY])


def test_canonical_mutation_and_capability_refusals():
    raw=encoded([rule()])
    for changed in [raw+b' ',raw.replace(b'18081',b'18082'),raw.replace(b'"network":',b'"extra":1,"network":')]:
        with pytest.raises(ValueError):compile_network(changed,digest(raw),[CAPABILITY])
    with pytest.raises(ValueError):compile_network(raw,digest(raw),[CAPABILITY,'extra/v1'])
    with pytest.raises(ValueError):compile_network(raw+b' ',digest(raw+b' '),[CAPABILITY])


def test_over_capacity_refused():
    raw=encoded([rule('10.0.0.1',p) for p in range(1,4098)])
    with pytest.raises(ValueError):compile_network(raw,digest(raw),[CAPABILITY])
