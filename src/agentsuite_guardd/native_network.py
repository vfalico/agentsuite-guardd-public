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
from .target import validate_cgroup_fd, cgroup_removed, TargetNotLive

class Native:
    PROGRAMS={'connect4':('cgroup',10),'egress':('cgroup',1),'socket_create':('lsm',None),'file_receive':('lsm',None),'socket_accept':('lsm',None),'socket_bind':('lsm',None),'socket_connect':('lsm',None),'socket_sendmsg':('lsm',None)}
    MAPS = {'endpoints': ('hash', 8, 4, 4096), 'targets': ('hash', 8, 4, 1)}
    HOOKS = {}
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
        if not p:
            raise OSError(errno.ENOENT, "required native BPF object/program is absent")
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
    def entries(self, cgroup, endpoints):
        cg = validate_cgroup_fd(cgroup)
        return {
            'endpoints': {ipaddress.IPv4Address(a).packed + struct.pack('=I', p): struct.pack('=I', 1) for a, p in endpoints},
            'targets': {struct.pack('=Q', cg.cgroup_id): struct.pack('=I', 1)},
        }

    def install(self,directory,cgroup,endpoints):
        directory=Path(directory); directory.mkdir(mode=0o700)
        obj=self.pointer(self.lib.bpf_object__open_file(self.path.encode(),None));links=[]
        try:
            self.checked(self.lib.bpf_object__load(obj))
            maps={name:self.checked(self.lib.bpf_object__find_map_fd_by_name(obj,name.encode())) for name in self.MAPS}
            # Pin maps before mutation; uncertain failure always has a journaled owner.
            for name,fd in maps.items():self.checked(self.lib.bpf_obj_pin(fd,str(directory/name).encode()))
            for name, entries in self.entries(cgroup, endpoints).items():
                for key, value in entries.items():
                    self.checked(self.lib.bpf_map_update_elem(maps[name],C.create_string_buffer(key),C.create_string_buffer(value),0))
            for name, fd in maps.items():
                if self.MAPS[name][0] != 'ringbuf':
                    self.checked(self.lib.bpf_map_freeze(fd))
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
        expected_names=set(self.MAPS)|{n+s for n in self.PROGRAMS for s in ['-prog','-link']}
        if {p.name for p in directory.iterdir()}!=expected_names:raise ValueError('network pinned inventory mismatch')
        for name,(kind,size,value_size,count) in self.MAPS.items():
            path=directory/name
            fd=self.checked(self.lib.bpf_obj_get(str(path).encode()));os.close(fd)
            m=self.info('map',path)
            if m['type']!=kind or m['bytes_key']!=size or m['bytes_value']!=value_size or m['max_entries']!=count or m.get('flags',0)!=0 or (kind != 'ringbuf' and not m.get('frozen',0)):raise ValueError('native map ABI mismatch')
            proof['maps'][name]=m
        def byte_array(value):
            if isinstance(value,dict):value=value.get('bytes',value)
            if not isinstance(value,list):raise ValueError('unexpected bpftool map byte encoding')
            return bytes(int(v,16) if isinstance(v,str) else v for v in value)
        for name, expected in self.entries(cgroup, endpoints).items():
            rows = self.dump(directory/name)
            actual={byte_array(e['key']):byte_array(e['value']) for e in rows}
            if len(rows) != len(actual) or actual!=expected:raise ValueError('complete native map readback mismatch: '+name)
        owned={m['id'] for m in proof['maps'].values()}
        # BTF is immutable while referenced by the pinned programs. Parse each
        # object once within this readback, never reuse it across verify calls.
        btf_names = {}
        for name,(kind,attach) in self.PROGRAMS.items():
            p=self.info('prog',directory/(name+'-prog'));link=self.info('link',directory/(name+'-link'))
            # bpftool can report the full BTF function name instead of the
            # kernel's 15-byte object name. Neither spelling weakens the
            # independent program/link, private-map and hook-BTF checks below.
            if p['name'] not in {name, name[:15]} or not set(p.get('map_ids',[]))<=owned or link['prog_id']!=p['id']:raise ValueError('network program/link identity mismatch')
            if kind=='cgroup':
                if link['type']!='cgroup' or link['attach_type'] not in [attach, {10:'cgroup_inet4_connect',1:'cgroup_inet_egress',14:'cgroup_udp4_sendmsg'}[attach]]:raise ValueError('network cgroup attachment mismatch')
                if link['cgroup_id'] != cg.cgroup_id:
                    if type(link['cgroup_id']) is int and link['cgroup_id'] == 0 and cgroup_removed(cgroup):
                        raise TargetNotLive('network cgroup target was removed during readback')
                    raise ValueError('network cgroup attachment mismatch')
            else:
                if link['type']!='tracing' or p['type']!='lsm':raise ValueError('network LSM attachment mismatch')
                # The loaded CO-RE program's attach BTF identity must name the exact LSM hook.
                fd=self.checked(self.lib.bpf_obj_get(str(directory/(name+'-prog')).encode()))
                try:
                    buf=C.create_string_buffer(232);size=C.c_uint32(232)
                    self.checked(self.lib.bpf_obj_get_info_by_fd(fd,buf,C.byref(size)))
                    btf_obj,btf_id=struct.unpack_from('=II',buf.raw,220)
                finally: os.close(fd)
                if btf_obj not in btf_names:
                    if not btf_obj:
                        args=['bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw']
                    else: args=['bpftool','-j','btf','dump','id',str(btf_obj),'format','raw']
                    btf=json.loads(subprocess.check_output(args,timeout=10))
                    types=btf.get('types',btf) if isinstance(btf,dict) else btf
                    btf_names[btf_obj] = {t['id']: t.get('name') for t in types}
                    del btf, types
                hook = self.HOOKS.get(name, name)
                if btf_names[btf_obj].get(btf_id) not in ['bpf_lsm_'+hook,'security_'+hook]:raise ValueError('network LSM hook identity mismatch')
            proof['programs'][name]=p;proof['links'][name]=link
        if len({v['id'] for v in proof['links'].values()})!=len(self.PROGRAMS):raise ValueError('duplicate network links')
        return proof
