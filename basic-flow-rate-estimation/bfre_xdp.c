// bfre.c
#define ETH_P_IP 0x0800

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct flow_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
};

struct flow_stats_bfre {
    __u64 last_ts_ns;
    __u64 bytes;
    __u64 rate_bps;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_id);
    __type(value, struct flow_stats_bfre);
    __uint(max_entries, 10240);
} flow_map SEC(".maps");


// Ayuda para parsear paquetes IPv4/TCP/UDP
static __always_inline int parse_ipv4_5tuple(struct xdp_md *ctx, struct flow_id *key) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;

    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end) return -1;
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
      if ((void *)(udp + 1) > data_end) return -1;
        key->src_port = udp->source;
        key->dst_port = udp->dest;
    } else {
        return -1;
    }

    return 0;
}

SEC("xdp")
int bfre_xdp_prog(struct xdp_md *ctx) {
    struct flow_id key = {};
    struct flow_stats_bfre *stats, new_stats = {};
    __u64 now = bpf_ktime_get_ns();

    if (parse_ipv4_5tuple(ctx, &key) < 0)
        return XDP_PASS;

    stats = bpf_map_lookup_elem(&flow_map, &key);
    if (stats) {
        __u64 delta = now - stats->last_ts_ns;
        if (delta > 0) {
            stats->rate_bps = (ctx->data_end - ctx->data) * 1000000000ULL / delta;
            stats->bytes += ctx->data_end - ctx->data;
            stats->last_ts_ns = now;
        }
    } else {
        new_stats.last_ts_ns = now;
        new_stats.bytes = ctx->data_end - ctx->data;
        bpf_map_update_elem(&flow_map, &key, &new_stats, BPF_ANY);
    }

    return XDP_PASS;
}
