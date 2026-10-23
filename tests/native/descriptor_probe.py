#!/usr/bin/env python3
"""Native primitive descriptor discriminator, not runtime integration acceptance."""
import array,base64,hashlib,json,os,pathlib,select,socket,struct,subprocess,sys,time
from agentsuite_guardd.neutral_service import Service,target_identity
from agentsuite_guardd.native_network import Native
root=pathlib.Path(sys.argv[1]);root.mkdir(mode=0o700,exist_ok=False)
cgroot=pathlib.Path('/sys/fs/cgroup/poc-fds-'+root.name);cgroot.mkdir()
pins=pathlib.Path('/sys/fs/bpf/poc-fds-'+root.name);pins.mkdir()
service=Service(root/'state.db',pins,Native(sys.argv[2]));records=[];resources=[]
childcode=r'''import array,json,os,socket,sys
open(sys.argv[1],'w').write(str(os.getpid()))
a=socket.socket(fileno=int(sys.argv[2]));d=socket.socket(fileno=int(sys.argv[3]));u=socket.socket(fileno=int(sys.argv[4]))
os.setgroups([]);os.setgid(61234);os.setuid(61234)
print('HELD',flush=True);sys.stdin.readline();out={}
for name,s in [('inherited_allow',a),('inherited_deny',d),('foreign_unix',u)]:
 try:s.sendall(name.encode());out[name]='sent'
 except OSError as e:out[name]=repr(e)
try:
 raw,anc,flags,_=u.recvmsg(1,socket.CMSG_SPACE(4));fds=array.array('i')
 for level,kind,value in anc:
  if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:fds.frombytes(value[:len(value)//4*4])
 if fds:
  z=socket.socket(fileno=fds[0]);z.sendall(b'delegated-deny');z.close();out['delegated_deny']='sent'
 else:out['delegated_deny']='no received fd'
except OSError as e:out['delegated_deny']=repr(e)
for name,port in [('fresh_allow',sys.argv[5]),('fresh_deny',sys.argv[6])]:
 try:
  s=socket.socket();s.settimeout(.5);s.connect(('127.0.0.1',int(port)));s.sendall(name.encode());s.close();out[name]='sent'
 except OSError as e:out[name]=repr(e)
try:
 x,y=socket.socketpair();x.sendall(b'internal');out['internal_unix']=y.recv(32).decode();x.close();y.close()
except OSError as e:out['internal_unix']=repr(e)
print(json.dumps(out),flush=True);sys.stdin.readline()
'''
def connect(listener):
 s=socket.socket();s.connect(listener.getsockname());other,_=listener.accept();resources.extend([s,other]);return s,other
def listener():
 s=socket.socket();s.bind(('127.0.0.1',0));s.listen(8);resources.append(s);return s
allow=listener();deny=listener()
raw=json.dumps(dict(version='agentsuite.policy/v2',network=dict(egressAllow=[dict(address='127.0.0.1',port=allow.getsockname()[1],protocol='TCP')]),requiredCapabilities=['network/egress-allow/v1']),sort_keys=True,separators=(',',':')).encode()
req=dict(format='agentsuite.policy/v2',bytes=base64.b64encode(raw).decode(),digest='sha256:'+hashlib.sha256(b'agentsuite-effective-policy\0v1\0'+struct.pack('>Q',len(raw))+raw).hexdigest(),capabilities=['network/egress-allow/v1'])
try:
 for mode in ['control','governed']:
  cg=cgroot/mode;cg.mkdir();fd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY)
  a,ar=connect(allow);d,dr=connect(deny);delegated,delegatedr=connect(deny);u,v=socket.socketpair();resources.extend([u,v])
  p=subprocess.Popen([sys.executable,'-c',childcode,str(cg/'cgroup.procs'),str(a.fileno()),str(d.fileno()),str(v.fileno()),str(allow.getsockname()[1]),str(deny.getsockname()[1])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,pass_fds=(a.fileno(),d.fileno(),v.fileno()))
  pidfd=os.pidfd_open(p.pid);ns=os.open('/proc/'+str(p.pid)+'/ns/net',os.O_RDONLY);item=dict(p=p,cg=cg,fd=fd,pidfd=pidfd,ns=ns,target=None,mode=mode);records.append(item)
  assert p.stdout.readline().strip()=='HELD'
  target=target_identity(fd);target.update(pid=p.pid,start=pathlib.Path('/proc/'+str(p.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19],netns=os.fstat(ns).st_ino,generation=1);item['target']=target
  def call(method):return service.dispatch(dict(version='execution-enforcement/v1',method=method,operation=mode,requirement=req,target=target),[fd,pidfd,ns] if method=='activate' else [fd])
  if mode=='governed':print('ACTIVATED',json.dumps(call('activate')),flush=True)
  u.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[delegated.fileno()]))]);p.stdin.write('probe\n');p.stdin.flush()
  ready,_,_=select.select([p.stdout],[],[],8);assert ready,'child timed out';effects=json.loads(p.stdout.readline());arrivals={}
  for name,s in [('inherited_allow',ar),('inherited_deny',dr),('delegated_deny',delegatedr),('foreign_unix',u)]:
   ready,_,_=select.select([s],[],[],.15);arrivals[name]=s.recv(128).decode() if ready else None
  for name,l in [('fresh_allow',allow),('fresh_deny',deny)]:
   ready,_,_=select.select([l],[],[],.15)
   if ready:c,_=l.accept();arrivals[name]=c.recv(128).decode();c.close()
   else:arrivals[name]=None
  result=dict(mode=mode,target=target,requirement=req,effects=effects,receiver=arrivals);(root/(mode+'.json')).write_text(json.dumps(result,indent=2));print('RESULT',json.dumps(result),flush=True)
  if mode=='control':
   assert all(effects[k]=='sent' and arrivals[k] for k in ['inherited_allow','inherited_deny','delegated_deny','fresh_allow','fresh_deny','foreign_unix']),result
  else:
   assert effects['inherited_allow']=='sent' and arrivals['inherited_allow'] and effects['fresh_allow']=='sent' and arrivals['fresh_allow'],result
   assert all(effects[k]!='sent' and arrivals[k] is None for k in ['inherited_deny','delegated_deny','fresh_deny','foreign_unix']),result
  assert effects['internal_unix']=='internal',result
  p.stdin.write('stop\n');p.stdin.flush();p.wait(timeout=5);assert p.returncode==0,p.stderr.read()
  if mode=='governed':print('RETIRED',json.dumps(call('retire')),flush=True)
 print('DESCRIPTOR_DISCRIMINATOR_COMPLETE',flush=True)
finally:
 for i in records:
  p=i['p']
  if p.poll() is None:p.terminate();p.wait(timeout=5)
  if i['mode']=='governed' and i['target']:
   try:service.dispatch(dict(version='execution-enforcement/v1',method='retire',operation=i['mode'],requirement=req,target=i['target']),[i['fd']])
   except Exception as e:print('RETAINED_OWNER',repr(e),flush=True)
  for k in ['fd','pidfd','ns']:os.close(i[k])
  i['cg'].rmdir()
 service.close()
 for s in resources:s.close()
 cgroot.rmdir();pins.rmdir()
