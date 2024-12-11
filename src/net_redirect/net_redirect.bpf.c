#include "net_redirect.h"

#include <linux/bpf.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10);
} snat_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10);
} dnat_map SEC(".maps");

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline __u16 update_checksum(__u16 old_csum, __u16 old_val,
                                             __u16 new_val)
{
    __u32 csum = (~old_csum & 0xFFFF) + (~old_val & 0xFFFF) + new_val;
    csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

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
int xdp_redirect_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int action = XDP_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        action = XDP_DROP;
        goto out;
    }

    if (eth->h_proto != htons(ETH_P_IP)) goto out;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
    {
        action = XDP_DROP;
        goto out;
    }

    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_ICMP &&
        protocol != IPPROTO_UDP)
    {
        goto out;
    }

    __u32 old_src_ip = ip->saddr;
    __u32 old_dst_ip = ip->daddr;
    __u16 original_checksum = ip->check;

    __u32 *new_dst_ip = bpf_map_lookup_elem(&dnat_map, &old_dst_ip);
    if (new_dst_ip)
    {
        ip->daddr = *new_dst_ip;
        ip->check = update_checksum(original_checksum, (__u16)(old_dst_ip >> 16),
                                    (__u16)(*new_dst_ip >> 16));
        ip->check = update_checksum(ip->check, (__u16)(old_dst_ip & 0xFFFF),
                                    (__u16)(*new_dst_ip & 0xFFFF));
        goto out;
    }

    __u32 *new_src_ip = bpf_map_lookup_elem(&snat_map, &old_src_ip);
    if (new_src_ip)
    {
        ip->saddr = *new_src_ip;
        ip->check = update_checksum(original_checksum, (__u16)(old_src_ip >> 16),
                                    (__u16)(*new_src_ip >> 16));
        ip->check = update_checksum(ip->check, (__u16)(old_src_ip & 0xFFFF),
                                    (__u16)(*new_src_ip & 0xFFFF));
    }

out:
    return xdp_stats_record_action(ctx, action);
}