#include <linux/bpf.h>
#include "bpf_helpers_min.h"

SEC("xdp")
int xdp_pass_probe(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
