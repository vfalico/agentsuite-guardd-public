// SPDX-License-Identifier: Apache-2.0
// Included after program.bpf.c: both capabilities share its target/generation.
#include <bpf/bpf_endian.h>

struct container_endpoint { __u32 address; __u32 port; __u32 protocol; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct container_endpoint);
    __type(value, __u32);
} container_endpoints SEC(".maps");

static __always_inline int network_allowed(__u32 address, __u32 port, __u32 protocol)
{
    struct container_endpoint endpoint = { address, port, protocol };
    __u32 *value = bpf_map_lookup_elem(&container_endpoints, &endpoint);
    if (value && *value == 1)
        return 1;
    endpoint.port = 0; // An all-ports grant must be explicit in the policy.
    value = bpf_map_lookup_elem(&container_endpoints, &endpoint);
    return value && *value == 1;
}

static __always_inline long network_denied(void)
{
    long value = -EACCES;
    asm volatile("" : "+r"(value));
    return value;
}

static __always_inline int network_address(struct bpf_sock_addr *ctx)
{
    __u32 type = ctx->type, protocol = ctx->protocol;
    // Keep LLVM from rematerializing a context pointer through branch PHIs.
    asm volatile("" : "+r"(protocol));
    if (!((type == 1 && protocol == 6) || (type == 2 && protocol == 17)))
        return 0;
    return network_allowed(ctx->user_ip4, bpf_ntohs(ctx->user_port), protocol);
}

SEC("cgroup/connect4")
int network_connect4(struct bpf_sock_addr *ctx) { return network_address(ctx); }
SEC("cgroup/sendmsg4")
int network_sendmsg4(struct bpf_sock_addr *ctx) { return network_address(ctx); }

SEC("cgroup_skb/egress")
int network_egress(struct __sk_buff *skb)
{
    unsigned char ip[20], transport[20];
    if (skb->protocol != bpf_htons(0x0800) || bpf_skb_load_bytes(skb, 0, ip, 20))
        return 0;
    __u32 ihl = (ip[0] & 15) * 4, total = ((__u32)ip[2] << 8) | ip[3];
    if (ip[0] >> 4 != 4 || ihl < 20 || ihl > 60 || total > skb->len ||
        (ip[6] & 0x3f) || ip[7])
        return 0;
    __u32 minimum = ip[9] == 6 ? 20 : ip[9] == 17 ? 8 : 0;
    if (!minimum || total < ihl + minimum)
        return 0;
    if (ip[9] == 6) {
        if (bpf_skb_load_bytes(skb, ihl, transport, 20))
            return 0;
        __u32 length = (transport[12] >> 4) * 4;
        if (length < 20 || total < ihl + length)
            return 0;
    } else {
        if (bpf_skb_load_bytes(skb, ihl, transport, 8))
            return 0;
        __u32 length = ((__u32)transport[4] << 8) | transport[5];
        if (length < 8 || length != total - ihl)
            return 0;
    }
    __u32 address;
    __builtin_memcpy(&address, &ip[16], 4);
    return network_allowed(address, ((__u32)transport[2] << 8) | transport[3], ip[9]);
}

SEC("lsm/socket_create")
long BPF_PROG(network_socket_create, int family, int type, int protocol, int kern, long ret)
{
    if (ret) return ret;
    if (!governed_generation()) return 0;
    return ((family == 1 && (type & 15) == 1 && protocol == 0) ||
            (family == 2 && (((type & 15) == 1 && (protocol == 0 || protocol == 6)) ||
                             ((type & 15) == 2 && (protocol == 0 || protocol == 17))))) ?
        0 : network_denied();
}

SEC("lsm/file_receive")
long BPF_PROG(network_file_receive, struct file *file, long ret)
{
    if (ret) return ret;
    if (!governed_generation()) return 0;
    return (BPF_CORE_READ(file, f_inode, i_mode) & 0170000) == 0140000 ?
        network_denied() : 0;
}

static __always_inline int network_tcp_socket(struct socket *sock)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return sk && BPF_CORE_READ(sk, __sk_common.skc_family) == 2 &&
        BPF_CORE_READ(sock, type) == 1 && BPF_CORE_READ(sk, sk_protocol) == 6;
}

SEC("lsm/socket_accept")
long BPF_PROG(network_socket_accept, struct socket *sock, struct socket *newsock, long ret)
{
    if (ret) return ret;
    if (!governed_generation()) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    unsigned short family = sk ? BPF_CORE_READ(sk, __sk_common.skc_family) : 0;
    // A dual-stack listener also accepts IPv4; authorize its peer at send time.
    return sk && (family == 2 || family == 10) &&
        BPF_CORE_READ(sock, type) == 1 && BPF_CORE_READ(sk, sk_protocol) == 6 ?
        0 : network_denied();
}

SEC("lsm/socket_bind")
long BPF_PROG(network_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, long ret)
{
    if (ret) return ret;
    if (!governed_generation()) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return sk && BPF_CORE_READ(sk, __sk_common.skc_family) == 2 &&
        (network_tcp_socket(sock) ||
         (BPF_CORE_READ(sock, type) == 2 && BPF_CORE_READ(sk, sk_protocol) == 17)) ?
        0 : network_denied();
}

SEC("lsm/socket_connect")
long BPF_PROG(network_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, long ret)
{
    if (ret) return ret;
    if (!governed_generation()) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk || BPF_CORE_READ(sk, __sk_common.skc_family) != 2)
        return network_denied();
    __u32 protocol = BPF_CORE_READ(sk, sk_protocol);
    if (!((protocol == 6 && BPF_CORE_READ(sock, type) == 1) ||
          (protocol == 17 && BPF_CORE_READ(sock, type) == 2)))
        return network_denied();
    struct sockaddr_in destination = {};
    if (addrlen < sizeof(destination) ||
        bpf_probe_read_kernel(&destination, sizeof(destination), address) ||
        destination.sin_family != 2)
        return network_denied();
    return network_allowed(destination.sin_addr.s_addr, bpf_ntohs(destination.sin_port), protocol) ?
        0 : network_denied();
}

SEC("lsm/socket_sendmsg")
long BPF_PROG(network_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size, long ret)
{
    if (ret) return ret;
    if (!governed_generation()) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return network_denied();
    unsigned short family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == 1) {
        struct cgroup *owner = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
        struct sock *peer = BPF_CORE_READ((struct unix_sock *)sk, peer);
        struct cgroup *peer_owner = peer ? BPF_CORE_READ(peer, sk_cgrp_data.cgroup) : 0;
        __u64 current = bpf_get_current_cgroup_id();
        // A listener's accepted endpoint can inherit the connecting task's
        // cgroup. Only unbound socketpairs are supported, never listener peers.
        if (!peer || BPF_CORE_READ(sock, type) != 1 ||
            BPF_CORE_READ_BITFIELD_PROBED(peer, sk_type) != 1 ||
            BPF_CORE_READ((struct unix_sock *)sk, addr) ||
            BPF_CORE_READ((struct unix_sock *)peer, addr))
            return network_denied();
        return owner && peer_owner && BPF_CORE_READ(owner, kn, id) == current &&
            BPF_CORE_READ(peer_owner, kn, id) == current ? 0 : network_denied();
    }
    __u32 protocol = BPF_CORE_READ(sk, sk_protocol);
    if (family == 10 && protocol == 6 && BPF_CORE_READ(sock, type) == 1) {
        struct in6_addr peer = {};
        if (bpf_core_read(&peer, sizeof(peer), &sk->__sk_common.skc_v6_daddr) ||
            peer.in6_u.u6_addr32[0] || peer.in6_u.u6_addr32[1] ||
            peer.in6_u.u6_addr32[2] != bpf_htonl(0xffff))
            return network_denied();
        return network_allowed(peer.in6_u.u6_addr32[3],
            bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), protocol) ?
            0 : network_denied();
    }
    if (family != 2 || !((protocol == 6 && BPF_CORE_READ(sock, type) == 1) ||
                         (protocol == 17 && BPF_CORE_READ(sock, type) == 2)))
        return network_denied();
    __u32 address = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u32 port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (protocol == 17 && BPF_CORE_READ(msg, msg_name)) {
        struct sockaddr_in destination = {};
        if (BPF_CORE_READ(msg, msg_namelen) < sizeof(destination) ||
            bpf_probe_read_kernel(&destination, sizeof(destination), BPF_CORE_READ(msg, msg_name)) ||
            destination.sin_family != 2)
            return network_denied();
        address = destination.sin_addr.s_addr;
        port = bpf_ntohs(destination.sin_port);
    }
    return network_allowed(address, port, protocol) ? 0 : network_denied();
}
