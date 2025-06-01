  GNU nano 6.2                               xdp_par.c                                        

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_cnt SEC(".maps");


SEC("xdp")
int xdp_packet_rate(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&packet_cnt, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);  // atomic increment
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";