#include "tc_nat.h"

#include <linux/bpf.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

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
    __type(key, struct nat_key_t);
    __type(value, struct nat_value_t);
    __uint(max_entries, 10);
} snat_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_key_t);
    __type(value, struct nat_value_t);
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
    if (action >= 3) return 0;

    struct datarec *rec = bpf_map_lookup_elem(&tc_stats_map, &action);
    if (!rec) return 0;

    __u64 bytes = (void *)(long)skb->data_end - (void *)(long)skb->data;
    rec->rx_packets++;
    rec->rx_bytes += bytes;

    return TC_ACT_OK;
}

static __always_inline int process_packet(struct __sk_buff *skb, int is_dnat)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != htons(ETH_P_IP))
        return DEFAULT;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return DEFAULT;

    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return DEFAULT;

    __u32 old_ip = is_dnat ? ip->daddr : ip->saddr;
    __u16 original_checksum = ip->check;
    __u16 old_port = 0;

    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return DEFAULT;
        old_port = is_dnat ? tcp->dest : tcp->source;
    }
    else
    {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return DEFAULT;
        old_port = is_dnat ? udp->dest : udp->source;
    }

    struct nat_key_t key = {
        .ip = old_ip,
        .port = old_port,
        .protocol = protocol,
    };

    struct nat_value_t *value = is_dnat ? bpf_map_lookup_elem(&dnat_map, &key)
                                        : bpf_map_lookup_elem(&snat_map, &key);
    if (value)
    {
        if (is_dnat)
        {
            ip->daddr = value->ip;
        }
        else
        {
            ip->saddr = value->ip;
        }

        ip->check = update_checksum(original_checksum, (__u16)(old_ip >> 16),
                                    (__u16)(value->ip >> 16));
        ip->check = update_checksum(ip->check, (__u16)(old_ip & 0xFFFF),
                                    (__u16)(value->ip & 0xFFFF));

        if (protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            __u16 old_checksum = tcp->check;
            if (is_dnat)
            {
                tcp->dest = value->port;
            }
            else
            {
                tcp->source = value->port;
            }
            tcp->check = update_checksum(old_checksum, old_port,
                                         is_dnat ? value->port : value->port);
        }
        else
        {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            __u16 old_checksum = udp->check;
            if (is_dnat)
            {
                udp->dest = value->port;
            }
            else
            {
                udp->source = value->port;
            }
            udp->check = update_checksum(old_checksum, old_port,
                                         is_dnat ? value->port : value->port);
        }
        return is_dnat ? DNAT : SNAT;
    }
    return DEFAULT;
}

SEC("tc")
int tc_dnat_func(struct __sk_buff *skb)
{
    return tc_stats_record_action(skb, process_packet(skb, 1));
}

SEC("tc")
int tc_snat_func(struct __sk_buff *skb)
{
    return tc_stats_record_action(skb, process_packet(skb, 0));
}