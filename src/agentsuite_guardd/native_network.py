"""Native libbpf target backend with complete kernel-state readback.

Only the loader and complete readback are reused; no historical transport,
Orka binding schema, singleton admission or workload controller is imported.
"""
from __future__ import annotations
import ctypes as C
import errno
import ipaddress
import json
import os
import struct
import subprocess
from pathlib import Path
from .target import validate_cgroup_fd

class Native:
    PROGRAMS={'connect4':('cgroup',10),'egress':('cgroup',1),'socket_create':('lsm',None),'file_receive':('lsm',None),'socket_accept':('lsm',None),'socket_bind':('lsm',None),'socket_connect':('lsm',None),'socket_sendmsg':('lsm',None)}
    def __init__(self,obj):
        self.path=str(Path(obj).resolve()); self.lib=C.CDLL('libbpf.so.1',use_errno=True)
        signatures={
          'bpf_object__open_file':(C.c_void_p,[C.c_char_p,C.c_void_p]),
          'libbpf_get_error':(C.c_long,[C.c_void_p]),'bpf_object__load':(C.c_int,[C.c_void_p]),
          'bpf_object__close':(None,[C.c_void_p]),
          'bpf_object__find_map_fd_by_name':(C.c_int,[C.c_void_p,C.c_char_p]),
          'bpf_object__find_program_by_name':(C.c_void_p,[C.c_void_p,C.c_char_p]),
          'bpf_program__fd':(C.c_int,[C.c_void_p]),
          'bpf_program__attach_cgroup':(C.c_void_p,[C.c_void_p,C.c_int]),
          'bpf_program__attach_lsm':(C.c_void_p,[C.c_void_p]),
          'bpf_link__fd':(C.c_int,[C.c_void_p]),'bpf_link__destroy':(C.c_int,[C.c_void_p]),
          'bpf_obj_pin':(C.c_int,[C.c_int,C.c_char_p]),'bpf_obj_get':(C.c_int,[C.c_char_p]),
          'bpf_map_update_elem':(C.c_int,[C.c_int,C.c_void_p,C.c_void_p,C.c_ulonglong]),
          'bpf_map_freeze':(C.c_int,[C.c_int]),
          'bpf_obj_get_info_by_fd':(C.c_int,[C.c_int,C.c_void_p,C.POINTER(C.c_uint32)]),
        }
        for name,(restype,args) in signatures.items():
            fn=getattr(self.lib,name);fn.restype=restype;fn.argtypes=args
    def pointer(self,p):
        e=self.lib.libbpf_get_error(p)
        if e: raise OSError(-e,os.strerror(-e))
        return p
    @staticmethod
    def checked(n):
        if n<0:
            e=C.get_errno();raise OSError(e,os.strerror(e))
        return n
    def object_exists(self, kind, object_id):
        """Exact kernel-ID lookup: ENOENT alone proves absence.

        Do not infer absence from bpftool human diagnostics or its version-
        dependent JSON error rendering. A successful lookup temporarily owns
        one FD and must release it before the next absence observation.
        """
        if kind not in {"map", "link", "prog"}:
            raise ValueError("unsupported BPF object kind")
        if type(object_id) is not int or not 0 < object_id <= 0xffffffff:
            raise ValueError("invalid BPF object id")
        lookup = getattr(self.lib, "bpf_" + kind + "_get_fd_by_id")
        lookup.argtypes = [C.c_uint32]
        lookup.restype = C.c_int
        C.set_errno(0)
        fd = lookup(object_id)
        if fd < 0:
            error = C.get_errno()
            if error == errno.ENOENT:
                return False
            raise OSError(error, os.strerror(error))
        os.close(fd)
        return True

    @staticmethod
    def info(kind,path):
        result=subprocess.run(['bpftool','-j',kind,'show','pinned',str(path)],timeout=5,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        # Ubuntu bpftool returns 255 even with a complete valid link object;
        # accept only a parsed object, never empty/malformed output.
        data=json.loads(result.stdout)
        return data[0] if isinstance(data,list) else data
    @staticmethod
    def dump(path):
        return json.loads(subprocess.check_output(['bpftool','-j','map','dump','pinned',str(path)],timeout=5))
    def install(self,directory,cgroup,endpoints):
        directory=Path(directory); directory.mkdir(mode=0o700)
        obj=self.pointer(self.lib.bpf_object__open_file(self.path.encode(),None));links=[]
        try:
            self.checked(self.lib.bpf_object__load(obj))
            maps={name:self.checked(self.lib.bpf_object__find_map_fd_by_name(obj,name.encode())) for name in ['endpoints','targets']}
            # Pin maps before mutation; uncertain failure always has a journaled owner.
            for name,fd in maps.items():self.checked(self.lib.bpf_obj_pin(fd,str(directory/name).encode()))
            cg=validate_cgroup_fd(cgroup)
            for address,port in endpoints:
                key=C.create_string_buffer(ipaddress.IPv4Address(address).packed+struct.pack('=I',port));value=C.c_uint32(1)
                self.checked(self.lib.bpf_map_update_elem(maps['endpoints'],key,C.byref(value),0))
            key=C.c_uint64(cg.cgroup_id);value=C.c_uint32(1)
            self.checked(self.lib.bpf_map_update_elem(maps['targets'],C.byref(key),C.byref(value),0))
            for fd in maps.values():self.checked(self.lib.bpf_map_freeze(fd))
            for name,(kind,_) in self.PROGRAMS.items():
                program=self.pointer(self.lib.bpf_object__find_program_by_name(obj,name.encode()))
                self.checked(self.lib.bpf_obj_pin(self.lib.bpf_program__fd(program),str(directory/(name+'-prog')).encode()))
                link=self.pointer(self.lib.bpf_program__attach_cgroup(program,cgroup) if kind=='cgroup' else self.lib.bpf_program__attach_lsm(program))
                links.append(link)
                self.checked(self.lib.bpf_obj_pin(self.lib.bpf_link__fd(link),str(directory/(name+'-link')).encode()))
            return self.verify(directory,cgroup,endpoints)
        finally:
            for link in links:self.lib.bpf_link__destroy(link)
            self.lib.bpf_object__close(obj)
    def verify(self,directory,cgroup,endpoints):
        directory=Path(directory);cg=validate_cgroup_fd(cgroup);proof={'maps':{},'programs':{},'links':{}}
        expected_names={'endpoints','targets'}|{n+s for n in self.PROGRAMS for s in ['-prog','-link']}
        if {p.name for p in directory.iterdir()}!=expected_names:raise ValueError('network pinned inventory mismatch')
        for name,size,count in [('endpoints',8,4096),('targets',8,1)]:
            path=directory/name
            fd=self.checked(self.lib.bpf_obj_get(str(path).encode()));os.close(fd)
            m=self.info('map',path)
            if m['type']!='hash' or m['bytes_key']!=size or m['bytes_value']!=4 or m['max_entries']!=count or m.get('flags',0)!=0 or not m.get('frozen',0):raise ValueError('network map ABI mismatch')
            proof['maps'][name]=m
        def byte_array(value):
            if isinstance(value,dict):value=value.get('bytes',value)
            if not isinstance(value,list):raise ValueError('unexpected bpftool map byte encoding')
            return bytes(int(v,16) if isinstance(v,str) else v for v in value)
        actual={byte_array(e['key']):byte_array(e['value']) for e in self.dump(directory/'endpoints')}
        expected={ipaddress.IPv4Address(a).packed+struct.pack('=I',p):struct.pack('=I',1) for a,p in endpoints}
        if actual!=expected:raise ValueError('complete endpoint map readback mismatch')
        actual={byte_array(e['key']):byte_array(e['value']) for e in self.dump(directory/'targets')}
        if actual!={struct.pack('=Q',cg.cgroup_id):struct.pack('=I',1)}:raise ValueError('target map readback mismatch')
        owned={m['id'] for m in proof['maps'].values()}
        for name,(kind,attach) in self.PROGRAMS.items():
            p=self.info('prog',directory/(name+'-prog'));link=self.info('link',directory/(name+'-link'))
            if p['name']!=name or not set(p.get('map_ids',[]))<=owned or link['prog_id']!=p['id']:raise ValueError('network program/link identity mismatch')
            if kind=='cgroup':
                if link['type']!='cgroup' or link['cgroup_id']!=cg.cgroup_id or link['attach_type'] not in [attach, {10:'cgroup_inet4_connect',1:'cgroup_inet_egress'}[attach]]:raise ValueError('network cgroup attachment mismatch')
            else:
                if link['type']!='tracing' or p['type']!='lsm':raise ValueError('network LSM attachment mismatch')
                # The loaded CO-RE program's attach BTF identity must name the exact LSM hook.
                fd=self.checked(self.lib.bpf_obj_get(str(directory/(name+'-prog')).encode()))
                try:
                    buf=C.create_string_buffer(232);size=C.c_uint32(232)
                    self.checked(self.lib.bpf_obj_get_info_by_fd(fd,buf,C.byref(size)))
                    btf_obj,btf_id=struct.unpack_from('=II',buf.raw,220)
                finally: os.close(fd)
                if not btf_obj:
                    args=['bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw']
                else: args=['bpftool','-j','btf','dump','id',str(btf_obj),'format','raw']
                btf=json.loads(subprocess.check_output(args,timeout=10))
                types=btf.get('types',btf) if isinstance(btf,dict) else btf
                entry=next((t for t in types if t['id']==btf_id),None)
                if entry is None or entry.get('name') not in ['bpf_lsm_'+name,'security_'+name]:raise ValueError('network LSM hook identity mismatch')
            proof['programs'][name]=p;proof['links'][name]=link
        if len({v['id'] for v in proof['links'].values()})!=len(self.PROGRAMS):raise ValueError('duplicate network links')
        return proof
