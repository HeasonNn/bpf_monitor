#ifndef NAT_BPF_H
#define NAT_BPF_H

#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define DEFAULT 0
#define SNAT 1
#define DNAT 2
#define ACTION_MAX (DNAT + 1)

#define TC_ACT_OK 0

#define TCP_DST_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP_SRC_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

struct datarec {
  __u64 rx_packets;
  __u64 rx_bytes;
} __attribute__((aligned(8)));

struct nat_key_t {
  __u32 ip;
  __u16 port;
  __u8 protocol;
} __attribute__((packed));

struct nat_value_t {
  __u32 ip;
  __u16 port;
} __attribute__((aligned(2)));

#endif