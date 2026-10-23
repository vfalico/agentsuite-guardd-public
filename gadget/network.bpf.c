// Guardd native Suite network-v2 module. No private gadget ABI dependency.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
char LICENSE[] SEC("license") = "GPL";
struct endpoint { __u32 address; __u32 port; };
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4096); __type(key,struct endpoint); __type(value,__u32); } endpoints SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1); __type(key,__u64); __type(value,__u32); } targets SEC(".maps");
/* Keep denial a signed constant across LLVM boolean folding on older verifiers. */
static __always_inline long denied(void) { long value=-1; asm volatile("" : "+r"(value)); return value; }
static __always_inline int governed(void) {
 /* The target is a subtree, not just its current tasks. Runtime-created
  * descendants must not shed the LSM side of the ceiling. cgroup-v2 limits
  * hierarchy depth to 64; level zero names the root cgroup. */
 __u64 id=bpf_get_current_cgroup_id();
 if (bpf_map_lookup_elem(&targets,&id)) return 1;
 for (__u32 level=0;level<64;level++) {
  id=bpf_get_current_ancestor_cgroup_id(level);
  if (id && bpf_map_lookup_elem(&targets,&id)) return 1;
 }
 return 0;
}
static __always_inline int allowed(__u32 address,__u32 port) { struct endpoint e={address,port}; __u32 *v=bpf_map_lookup_elem(&endpoints,&e);return v && *v==1; }
SEC("cgroup/connect4") int connect4(struct bpf_sock_addr *ctx) {
 if(ctx->type!=1 || ctx->protocol!=6) return 0;
 return allowed(ctx->user_ip4, bpf_ntohs(ctx->user_port));
}
SEC("cgroup_skb/egress") int egress(struct __sk_buff *skb) {
 // cgroup skb begins at the network header (no Ethernet header). Reject all
 // non-IPv4 TCP, fragmentation, malformed headers, and ambiguous transport.
 unsigned char h[20];
 if(skb->protocol!=bpf_htons(0x0800)||bpf_skb_load_bytes(skb,0,h,20)) return 0;
 __u32 ihl=(h[0]&15)*4, total=((__u32)h[2]<<8)|h[3];
 if(h[0]>>4!=4 || ihl<20 || ihl>60 || total<ihl+20 || total>skb->len || h[9]!=6 || (h[6]&0x3f) || h[7]) return 0;
 unsigned char tcp[20]; if(bpf_skb_load_bytes(skb,ihl,tcp,20))return 0;
 __u32 thl=(tcp[12]>>4)*4; if(thl<20||total<ihl+thl)return 0;
 __u32 address; __builtin_memcpy(&address,&h[16],4);
 return allowed(address,((__u32)tcp[2]<<8)|tcp[3]);
}
SEC("lsm/socket_create") long BPF_PROG(socket_create,int family,int type,int protocol,int kern,long ret) {
 if(ret)return ret; if(!governed())return 0;
 return (family==1 && (type&15)==1 && protocol==0) || (family==2 && (type&15)==1 && (protocol==0||protocol==6)) ? 0 : denied();
}
SEC("lsm/file_receive") long BPF_PROG(file_receive,struct file *file,long ret) {
 if(ret)return ret; if(!governed())return 0;
 unsigned short mode=BPF_CORE_READ(file,f_inode,i_mode);
 return (mode&0170000)==0140000 ? denied() : 0;
}
SEC("lsm/socket_accept") long BPF_PROG(socket_accept,struct socket *sock,struct socket *newsock,long ret) {
 if(ret)return ret;if(!governed())return 0;
 // Egress-only ceiling: receiving IPv4 TCP does not grant reply authority.
 // Every reply still crosses current-sender sendmsg and cgroup skb checks.
 struct sock *sk=BPF_CORE_READ(sock,sk);
 return sk && BPF_CORE_READ(sk,__sk_common.skc_family)==2 && BPF_CORE_READ(sock,type)==1 && BPF_CORE_READ(sk,sk_protocol)==6 ? 0 : denied();
}
SEC("lsm/socket_bind") long BPF_PROG(socket_bind,struct socket *sock,struct sockaddr *address,int addrlen,long ret) {
 if(ret)return ret;if(!governed())return 0;
 // Egress-only ceiling: receiving IPv4 TCP does not grant reply authority.
 // Every reply still crosses current-sender sendmsg and cgroup skb checks.
 struct sock *sk=BPF_CORE_READ(sock,sk);
 return sk && BPF_CORE_READ(sk,__sk_common.skc_family)==2 && BPF_CORE_READ(sock,type)==1 && BPF_CORE_READ(sk,sk_protocol)==6 ? 0 : denied();
}

// Internal AF_UNIX socketpairs are needed by native ACP spawn. Ordinary Unix
// connect and bind are forbidden; received socket FDs are forbidden above.
SEC("lsm/socket_connect") long BPF_PROG(socket_connect,struct socket *sock,struct sockaddr *address,int addrlen,long ret) {
 if(ret)return ret;if(!governed())return 0;
 unsigned short family=BPF_CORE_READ(sock,sk,__sk_common.skc_family);
 return family==2 ? 0 : denied();
}

// A socket retains its creation cgroup after migration. cgroup_skb alone
// therefore cannot constrain sends on inherited foreign sockets. Check the
// CURRENT sender at the LSM hook; TCP/IPv4 reads its exact connected peer.
// Foreign AF_UNIX streams are refused to prevent delegation to an ungoverned
// local broker; native in-boundary socketpairs remain usable.
SEC("lsm/socket_sendmsg") long BPF_PROG(socket_sendmsg,struct socket *sock,struct msghdr *msg,int size,long ret) {
 if(ret)return ret;if(!governed())return 0;
 struct sock *sk=BPF_CORE_READ(sock,sk);if(!sk)return denied();
 unsigned short family=BPF_CORE_READ(sk,__sk_common.skc_family);
 if(family==1){
  struct cgroup *owner=BPF_CORE_READ(sk,sk_cgrp_data.cgroup);
  if(!owner)return denied();
  __u64 id=BPF_CORE_READ(owner,kn,id);
  return id==bpf_get_current_cgroup_id()?0:denied();
 }
 if(family!=2 || BPF_CORE_READ(sock,type)!=1 || BPF_CORE_READ(sk,sk_protocol)!=6)return denied();
 return allowed(BPF_CORE_READ(sk,__sk_common.skc_daddr),bpf_ntohs(BPF_CORE_READ(sk,__sk_common.skc_dport)))?0:denied();
}
