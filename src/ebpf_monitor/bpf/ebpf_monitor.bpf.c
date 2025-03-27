#include "ebpf_monitor.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct datarec);
  __uint(max_entries, STATS_TYPE_MAX);
} xdp_stats_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} ip_blacklist SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key);
  __type(value, __u8);
} ip_cidr_blacklist SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u16);
  __type(value, __u8);
} blocked_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct five_tuple);
  __type(value, __u8);
} firewall_rules SEC(".maps");

static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx,
                                                     __u32 type) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  if (type >= STATS_TYPE_MAX) return XDP_ABORTED;

  struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &type);
  if (!rec) return XDP_ABORTED;

  __u64 bytes = data_end - data;
  rec->rx_packets++;
  rec->rx_bytes += bytes;

  return STATS_TYPE_TO_XDP_ACTION(type);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;

  if (unlikely((void *)(eth + 1) > data_end))
    return xdp_stats_record_action(ctx, STATS_TYPE_DROPPED);

  if (unlikely(eth->h_proto != htons(ETH_P_IP) &&
               eth->h_proto != htons(ETH_P_IPV6)))
    return xdp_stats_record_action(ctx, STATS_TYPE_PASSED);

  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (unlikely((void *)(ip + 1) > data_end))
      return xdp_stats_record_action(ctx, STATS_TYPE_DROPPED);

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP &&
        protocol != IPPROTO_ICMP)
      return xdp_stats_record_action(ctx, STATS_TYPE_PASSED);

    // 1. 精确 IP 拦截
    if (bpf_map_lookup_elem(&ip_blacklist, &src_ip))
      return xdp_stats_record_action(ctx, STATS_TYPE_BLOCK);

    // 2. CIDR 段匹配
    struct lpm_key cidr_key = {.prefixlen = 24, .ip = src_ip};
    if (bpf_map_lookup_elem(&ip_cidr_blacklist, &cidr_key))
      return xdp_stats_record_action(ctx, STATS_TYPE_BLOCK);

    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
      if (unlikely((void *)(icmp + 1) > data_end))
        return xdp_stats_record_action(ctx, STATS_TYPE_DROPPED);
    }

    if (protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
      if (unlikely((void *)(tcp + 1) > data_end))
        return xdp_stats_record_action(ctx, STATS_TYPE_DROPPED);

      src_port = bpf_ntohs(tcp->source);
      dst_port = bpf_ntohs(tcp->dest);

    } else if (protocol == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)(ip + 1);
      if (unlikely((void *)(udp + 1) > data_end))
        return xdp_stats_record_action(ctx, STATS_TYPE_DROPPED);

      src_port = udp->source;
      dst_port = udp->dest;
    }

    // 3. 端口过滤（TCP/UDP）
    if (src_port && bpf_map_lookup_elem(&blocked_ports, &src_port))
      return xdp_stats_record_action(ctx, STATS_TYPE_BLOCK);
    if (dst_port && bpf_map_lookup_elem(&blocked_ports, &dst_port))
      return xdp_stats_record_action(ctx, STATS_TYPE_BLOCK);

    // 4. 五元组匹配
    struct five_tuple key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
    };
    if (bpf_map_lookup_elem(&firewall_rules, &key))
      return xdp_stats_record_action(ctx, STATS_TYPE_BLOCK);

  } else {  // IPv6
  }

  return xdp_stats_record_action(ctx, STATS_TYPE_PASSED);
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) { return XDP_PASS; }

char _license[] SEC("license") = "GPL";