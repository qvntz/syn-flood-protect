#include <uapi/linux/bpf.h>
#include <bpf_helpers.h>

SEC("prog")
int xdp_main(struct xdp_md* ctx) {
    return XDP_PASS; // пропускаем пакет в ядро
}

char _license[] SEC("license") = "GPL";
