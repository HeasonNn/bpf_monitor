#include "ebpf_nat.bpf.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, ACTION_MAX);
} ebpf_stats_map SEC(".maps");

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

static __always_inline __u32 ebpf_stats_record_action(struct __sk_buff *skb,
                                                    __u32 action)
{
    if (action >= 3) return 0;

    struct datarec *rec = bpf_map_lookup_elem(&ebpf_stats_map, &action);
    if (!rec) return 0;

    __u64 bytes = (void *)(long)skb->data_end - (void *)(long)skb->data;
    rec->rx_packets++;
    rec->rx_bytes += bytes;

    return TC_ACT_OK;
}

SEC("tc")
int ebpf_dnat_func(struct __sk_buff *skb)
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
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return DEFAULT;

    __u32 old_dst_ip = ip->daddr;
    __u16 original_checksum = ip->check;

    __u16 old_dst_port = 0;
    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return DEFAULT;
        old_dst_port = tcp->dest;
    }
    else if (protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return DEFAULT;
        old_dst_port = udp->dest;
    }

    struct nat_key_t dnat_key = {
        .ip = old_dst_ip,
        .port = old_dst_port,
        .protocol = protocol,
    };

    struct nat_value_t *dnat_value = bpf_map_lookup_elem(&dnat_map, &dnat_key);
    if (dnat_value)
    {
        if (protocol == IPPROTO_TCP)
        {
            bpf_skb_store_bytes(skb, IP_DST_OFF, &dnat_value->ip, sizeof(dnat_value->ip), BPF_F_RECOMPUTE_CSUM);
            bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_dst_ip, dnat_value->ip, sizeof(dnat_value->ip));

            bpf_skb_store_bytes(skb, TCP_DST_OFF, &dnat_value->port, sizeof(dnat_value->port), BPF_F_RECOMPUTE_CSUM);
            bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_dst_ip, dnat_value->ip, sizeof(dnat_value->ip) | BPF_F_PSEUDO_HDR);
            bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_dst_port, dnat_value->port, sizeof(dnat_value->port));
        }
        action = DNAT;
    }
    return ebpf_stats_record_action(skb, action);
}

SEC("tc")
int ebpf_snat_func(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int action = DEFAULT;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) goto out;

    if (eth->h_proto != htons(ETH_P_IP)) goto out;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) goto out;

    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) goto out;

    __u32 old_src_ip = ip->saddr;
    __u16 original_checksum = ip->check;

    __u16 old_src_port = 0;
    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) goto out;
        old_src_port = tcp->source;
    }
    else
    {
        goto out;
    }

    struct nat_key_t snat_key = {
        .ip = old_src_ip,
        .port = old_src_port,
        .protocol = protocol,
    };

    struct nat_value_t *snat_value = bpf_map_lookup_elem(&snat_map, &snat_key);
    if (snat_value)
    {
        if (protocol == IPPROTO_TCP)
        {
            bpf_skb_store_bytes(skb, IP_SRC_OFF, &snat_value->ip, sizeof(snat_value->ip), BPF_F_RECOMPUTE_CSUM);
            bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_src_ip, snat_value->ip, sizeof(snat_value->ip));

            bpf_skb_store_bytes(skb, TCP_SRC_OFF, &snat_value->port, sizeof(snat_value->port), BPF_F_RECOMPUTE_CSUM);
            bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_src_ip, snat_value->ip, sizeof(snat_value->ip) | BPF_F_PSEUDO_HDR);
            bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_src_ip, snat_value->port, sizeof(snat_value->port));
        }
        action = SNAT;
    }
    else
    {
        bpf_printk("SNAT miss");
    }

out:
    return ebpf_stats_record_action(skb, action);
}

char _license[] SEC("license") = "GPL";