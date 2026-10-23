"""Host-side exact netns interface boundary; experimental, no controller logic.

Ingress at the guest tap/veth precedes inet prerouting NAT/atunnel. One atomic
nft transaction binds two mandatory gates: ingress rejects non-ARP/non-TCP
frames and fragments; pre-DNAT prerouting admits exact IPv4 TCP endpoints or
tracked replies to host-initiated TCP connections. ARP
is link-neighbour discovery only; no IP traffic/DNS/UDP/IPv6 exemption exists.
"""
from __future__ import annotations
import hashlib
import json
import os
import subprocess

class NamespacePolicy:
    def __init__(self, nft='/usr/sbin/nft', nsenter='/usr/bin/nsenter'):
        self.nft = nft
        self.nsenter = nsenter

    def run(self, fd, args, data=None):
        command = [self.nsenter, '--net=/proc/self/fd/'+str(fd), '--', self.nft, '-j'] + args
        p = subprocess.run(command, input=json.dumps(data).encode() if data is not None else None,
                           pass_fds=(fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if p.returncode:
            raise RuntimeError('nft namespace transaction failed: '+p.stderr.decode(errors='replace'))
        return json.loads(p.stdout or b'{}')

    @staticmethod
    def name(operation):
        return 'ep_'+hashlib.sha256(operation.encode()).hexdigest()[:32]

    @staticmethod
    def desired(operation, interface, endpoints):
        table = NamespacePolicy.name(operation)
        chain = dict(family='netdev',table=table,name='boundary',type='filter',hook='ingress',dev=interface,prio=-500,policy='drop')
        prefix = dict(family='netdev',table=table,chain='boundary')
        arp = dict(prefix,expr=[{'match':{'op':'==','left':{'payload':{'protocol':'ether','field':'type'}},'right':'arp'}},{'accept':None}])
        # At ingress conntrack has not run. Admit only unfragmented IPv4 TCP
        # into the mandatory second gate, after conntrack but BEFORE DNAT.
        tcp = dict(prefix,expr=[
            {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'protocol'}},'right':'tcp'}},
            {'match':{'op':'==','left':{'&':[{'payload':{'protocol':'ip','field':'frag-off'}},16383]},'right':0}},
            {'accept':None}])
        commands = [{'add':{'table':dict(family='netdev',name=table)}},{'add':{'chain':chain}},{'add':{'rule':arp}},{'add':{'rule':tcp}},
            {'add':{'table':dict(family='inet',name=table)}},
            {'add':{'chain':dict(family='inet',table=table,name='boundary',type='filter',hook='prerouting',prio=-150,policy='accept')}}]
        prefix = dict(family='inet',table=table,chain='boundary')
        bound = {'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':interface}}
        # Only replies to host-initiated tracked TCP connections are exempt.
        # Established ORIGINAL traffic still needs an exact allowed endpoint.
        commands.append({'add':{'rule':dict(prefix,expr=[bound,
            {'match':{'op':'==','left':{'meta':{'key':'l4proto'}},'right':'tcp'}},
            {'match':{'op':'==','left':{'ct':{'key':'direction'}},'right':'reply'}},
            {'match':{'op':'==','left':{'ct':{'key':'state'}},'right':'established'}},
            {'accept':None}])}})
        for address,port in endpoints:
            expressions = [bound,
                {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'protocol'}},'right':'tcp'}},
                {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':address}},
                {'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':port}},
                {'accept':None}]
            commands.append({'add':{'rule':dict(prefix,expr=expressions)}})
        commands.append({'add':{'rule':dict(prefix,expr=[bound,{'drop':None}])}})
        return {'nftables':commands}

    @staticmethod
    def normalized(value):
        if isinstance(value,dict):
            return {k:NamespacePolicy.normalized(v) for k,v in value.items() if k not in {'handle','index','metainfo'}}
        if isinstance(value,list):return [NamespacePolicy.normalized(v) for v in value]
        return value

    def install(self,fd,operation,interface,endpoints):
        self.run(fd,['-f','-'],self.desired(operation,interface,endpoints))
        return self.verify(fd,operation,interface,endpoints)

    def verify(self,fd,operation,interface,endpoints):
        wanted=[v['add'] for v in self.desired(operation,interface,endpoints)['nftables']]
        actual=[]
        for family in ('netdev','inet'):
            dump=self.run(fd,['list','table',family,self.name(operation)])
            actual.extend(v for v in dump.get('nftables',[]) if 'metainfo' not in v)
        # nft 1.0.9 omits the netdev device in JSON; independently verify text.
        import shlex
        p=subprocess.run([self.nsenter,'--net=/proc/self/fd/'+str(fd),'--',self.nft,'-nn','list','chain','netdev',self.name(operation),'boundary'],pass_fds=(fd,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        tokens=shlex.split(p.stdout.decode())
        if p.returncode or tokens.count('device')!=1 or tokens[tokens.index('device')+1]!=interface:
            raise ValueError('namespace interface binding readback mismatch')
        wanted[1]['chain'].pop('dev')
        if self.normalized(actual)!=self.normalized(wanted):
            raise ValueError('complete namespace boundary readback mismatch: '+json.dumps(actual,sort_keys=True))
        return {'nftables':actual}

    @staticmethod
    def listed_tables(value):
        # A missing/malformed inventory is uncertainty, never an empty result.
        if type(value) is not dict or type(value.get('nftables')) is not list:
            raise ValueError('namespace table inventory is malformed')
        tables=[]
        for obj in value['nftables']:
            if type(obj) is not dict:
                raise ValueError('namespace table inventory entry is malformed')
            if set(obj)=={'metainfo'} and type(obj['metainfo']) is dict:
                continue
            if set(obj)!={'table'} or type(obj['table']) is not dict:
                raise ValueError('namespace table inventory object is malformed')
            table=obj['table']
            if type(table.get('family')) is not str or type(table.get('name')) is not str:
                raise ValueError('namespace table inventory identity is malformed')
            tables.append(table)
        return tables

    def remove(self,fd,operation,interface,endpoints):
        self.verify(fd,operation,interface,endpoints)
        self.run(fd,['-f','-'],{'nftables':[{'delete':{'table':dict(family=f,name=self.name(operation))}} for f in ('netdev','inet')]})
        tables=self.run(fd,['list','tables'])
        for table in self.listed_tables(tables):
            if table['family'] in {'netdev','inet'} and table['name']==self.name(operation):
                raise ValueError('namespace boundary residue')


    def interface(self, fd, name):
        # Kernel netlink interface identity, not caller-supplied JSON authority.
        result = subprocess.run([self.nsenter, '--net=/proc/self/fd/'+str(fd), '--',
            '/usr/sbin/ip', '-j', 'link', 'show', 'dev', name], pass_fds=(fd,),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if result.returncode:
            raise ValueError('exact interface unavailable: '+result.stderr.decode(errors='replace'))
        links = json.loads(result.stdout)
        if len(links) != 1:
            raise ValueError('ambiguous interface')
        item = links[0]
        return dict(index=item['ifindex'], name=item['ifname'], address=item['address'])
