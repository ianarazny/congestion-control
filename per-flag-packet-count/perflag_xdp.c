// perflag_xdp.c
#define ETH_P_IP  0x0800  // IPv4
#define ETH_P_ARP 0x0806  // ARP

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TCP_SYN 0
#define TCP_ACK 1
#define TCP_FIN 2
#define TCP_RST 3
#define UDP_IDX 4
#define TCP_IDX 5
#define IP_IDX 6
#define ARP_IDX 7
#define MAX_IDX 8

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_IDX);
    __type(key, __u32);
    __type(value, __u64);
} proto_flags_count SEC(".maps");

SEC("xdp")
int xdp_perflag_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    // ARP
    if (h_proto == ETH_P_ARP) {
        __u32 idx = ARP_IDX;
        __u64 *val = bpf_map_lookup_elem(&proto_flags_count, &idx);
        if (val) __sync_fetch_and_add(val, 1);
        return XDP_PASS;
    }

    // IP
    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __u32 idx = IP_IDX;
        __u64 *val = bpf_map_lookup_elem(&proto_flags_count, &idx);
        if (val) __sync_fetch_and_add(val, 1);

        // TCP
        if (iph->protocol == IPPROTO_TCP) {
            idx = TCP_IDX;
            val = bpf_map_lookup_elem(&proto_flags_count, &idx);
            if (val) __sync_fetch_and_add(val, 1);

            struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
            if ((void *)(tcph + 1) > data_end)
                return XDP_PASS;

            if (tcph->syn) {
                idx = TCP_SYN;
                val = bpf_map_lookup_elem(&proto_flags_count, &idx);
                if (val) __sync_fetch_and_add(val, 1);
            }
            if (tcph->ack) {
                idx = TCP_ACK;
                val = bpf_map_lookup_elem(&proto_flags_count, &idx);
                if (val) __sync_fetch_and_add(val, 1);
            }
            if (tcph->fin) {
                idx = TCP_FIN;
                val = bpf_map_lookup_elem(&proto_flags_count, &idx);
                if (val) __sync_fetch_and_add(val, 1);
            }
            if (tcph->rst) {
                idx = TCP_RST;
                val = bpf_map_lookup_elem(&proto_flags_count, &idx);
                if (val) __sync_fetch_and_add(val, 1);
            }

        } else if (iph->protocol == IPPROTO_UDP) {
            idx = UDP_IDX;
            val = bpf_map_lookup_elem(&proto_flags_count, &idx);
            if (val) __sync_fetch_and_add(val, 1);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
