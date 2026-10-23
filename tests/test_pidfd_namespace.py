"""Kernel metadata parsing/held-target checks; doubles are not native acceptance."""
import os
from pathlib import Path
from unittest.mock import patch
import pytest
from agentsuite_guardd.neutral_service import pidfd_identity, held_target

@pytest.mark.parametrize('text', [
    'Pid:\t-1\nNSpid:\t-1\n', 'Pid:\t0\nNSpid:\t0\n',
    'Pid:\t100\n', 'NSpid:\t100\n', 'Pid:\t100\nNSpid:\t101 10\n',
    'Pid:\t100\nNSpid:\t100 0\n', 'Pid:\t100\nPid:\t100\nNSpid:\t100\n',
    'Pid:\tx\nNSpid:\t100\n', 'flags:\t02000002\n'])
def test_reject_unusable_pidfd_metadata(text):
    with patch.object(Path, 'read_text', return_value=text):
        with pytest.raises(ValueError): pidfd_identity(7)

def test_kernel_nested_alias_is_not_global_numeric_adoption():
    with patch.object(Path,'read_text', return_value='Pid:\t1234\nNSpid:\t1234 42 7\n'):
        assert pidfd_identity(7)==(1234,[1234,42,7])

def test_real_own_pidfd_and_non_pidfd():
    fd=os.pidfd_open(os.getpid())
    try:
        pid, aliases=pidfd_identity(fd)
        assert pid==os.getpid() and aliases[0]==pid
    finally: os.close(fd)
    fd=os.open('/dev/null',os.O_RDONLY)
    try:
        with pytest.raises(ValueError): pidfd_identity(fd)
    finally: os.close(fd)

@pytest.mark.parametrize('mutation', ['none','wrong-alias','start','membership','namespace'])
def test_held_target_uses_receiver_pid_not_request_number(mutation):
    target=dict(boot='boot',cgroup=dict(dev=1,ino=2),pid=42,start='500',netns=9,generation=1)
    if mutation=='wrong-alias': target['pid']=99
    if mutation=='start': target['start']='501'
    metadata='Pid:\t1234\nNSpid:\t1234 42\n'
    def text(path,*a,**kw):
        name=str(path)
        if name=='/proc/self/fdinfo/7': return metadata
        if name=='/proc/1234/stat': return '1234 (held) '+' '.join(['0']*19+['500'])
        raise AssertionError('Unexpected proc lookup: '+name)
    class Stat: st_dev=3;st_ino=9
    def stat(path):
        assert path=='/proc/1234/ns/net'
        value=Stat()
        if mutation=='namespace':value.st_ino=10
        return value
    with patch.object(Path,'read_text',text), patch('agentsuite_guardd.neutral_service.target_identity',return_value=dict(boot='boot',cgroup=dict(dev=1,ino=2))),patch('agentsuite_guardd.neutral_service.task_ids',return_value=[99] if mutation=='membership' else [1234]),patch('agentsuite_guardd.neutral_service.os.fstat',return_value=Stat()),patch('agentsuite_guardd.neutral_service.os.stat',side_effect=stat):
        if mutation=='none':held_target([6,7,8],target)
        else:
            with pytest.raises(ValueError):held_target([6,7,8],target)
