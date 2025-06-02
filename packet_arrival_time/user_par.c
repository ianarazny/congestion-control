  GNU nano 6.2                              user_par.c                                        
#include <bpf/libbpf.h>
#include <bpf/bpf.h> 
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

int main() {
    const char *map_path = "/sys/fs/bpf/packet_cnt";
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    __u32 key = 0;
    __u64 prev = 0, curr = 0;

    // Leer valor inicial
    if (bpf_map_lookup_elem(map_fd, &key, &prev) != 0) {
        perror("bpf_map_lookup_elem");
        return 1;
    }

    while (1) {
        sleep(1);
        if (bpf_map_lookup_elem(map_fd, &key, &curr) == 0) {
            printf("Packet Arrival Rate: %llu pps\n", curr - prev);
            prev = curr;
        } else {
            perror("bpf_map_lookup_elem");
        }
    }

    return 0;
}