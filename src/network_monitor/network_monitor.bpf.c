/* SPDX-License-Identifier: GPL-2.0 */
#include "network_monitor.h"

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx,
                                                     __u32 action)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (action >= XDP_ACTION_MAX) return XDP_ABORTED;

    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (!rec) return XDP_ABORTED;

    __u64 bytes = data_end - data;
    rec->rx_packets++;
    rec->rx_bytes += bytes;

    return action;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    __u32 action = XDP_PASS;

    return xdp_stats_record_action(ctx, action);
}