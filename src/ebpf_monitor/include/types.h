#pragma once

#include <linux/types.h>

typedef enum stats_type {
  STATS_TYPE_ALLOWED = 0,  // Packet explicitly allowed by filter
  STATS_TYPE_BLOCK,        // Packet explicitly blocked by filter
  STATS_TYPE_PASSED,       // Packet passed through XDP without processing
  STATS_TYPE_DROPPED,      // Packet dropped due to errors
  STATS_TYPE_MAX
} stats_type_t;

struct datarec {
  __u64 rx_packets;
  __u64 rx_bytes;
};

struct lpm_key {
  __u32 prefixlen;
  __u32 ip;
};

struct five_tuple {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
};