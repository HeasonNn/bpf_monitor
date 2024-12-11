#include "tc_nat.h"

#include <linux/bpf.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define TC_ACT_OK 0

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, ACTION_MAX);
} tc_stats_map SEC(".maps");

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

static __always_inline __u16 update_checksum(__u16 old_csum, __u16 old_val,
                                             __u16 new_val)
{
    __u32 csum = (~old_csum & 0xFFFF) + (~old_val & 0xFFFF) + new_val;
    csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

static __always_inline __u32 tc_stats_record_action(struct __sk_buff *skb,
                                                    __u32 action)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    if (action >= 3) return 0;

    struct datarec *rec = bpf_map_lookup_elem(&tc_stats_map, &action);
    if (!rec) return 0;

    __u64 bytes = data_end - data;
    rec->rx_packets++;
    rec->rx_bytes += bytes;

    return TC_ACT_OK;
}

SEC("tc")
int tc_dnat_func(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int action = DEFAULT;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return DEFAULT;

    if (eth->h_proto != htons(ETH_P_IP)) return DEFAULT;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return DEFAULT;

    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_ICMP &&
        protocol != IPPROTO_UDP)
    {
        return DEFAULT;
    }

    __u32 old_dst_ip = ip->daddr;
    __u16 original_checksum = ip->check;

    __u32 *new_dst_ip = bpf_map_lookup_elem(&dnat_map, &old_dst_ip);
    if (new_dst_ip)
    {
        ip->daddr = *new_dst_ip;
        ip->check =
            update_checksum(original_checksum, (__u16)(old_dst_ip >> 16),
                            (__u16)(*new_dst_ip >> 16));
        ip->check = update_checksum(ip->check, (__u16)(old_dst_ip & 0xFFFF),
                                    (__u16)(*new_dst_ip & 0xFFFF));
        action = DNAT;
    }

    return tc_stats_record_action(skb, action);
}

SEC("tc")
int tc_snat_func(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int action = DEFAULT;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return DEFAULT;

    if (eth->h_proto != htons(ETH_P_IP)) return DEFAULT;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return DEFAULT;

    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_ICMP &&
        protocol != IPPROTO_UDP)
    {
        return DEFAULT;
    }

    __u32 old_src_ip = ip->saddr;
    __u16 original_checksum = ip->check;

    __u32 *new_src_ip = bpf_map_lookup_elem(&snat_map, &old_src_ip);
    if (new_src_ip)
    {
        ip->saddr = *new_src_ip;
        ip->check =
            update_checksum(original_checksum, (__u16)(old_src_ip >> 16),
                            (__u16)(*new_src_ip >> 16));
        ip->check = update_checksum(ip->check, (__u16)(old_src_ip & 0xFFFF),
                                    (__u16)(*new_src_ip & 0xFFFF));
        action = SNAT;
    }

    return tc_stats_record_action(skb, action);
}

char _license[] SEC("license") = "GPL";