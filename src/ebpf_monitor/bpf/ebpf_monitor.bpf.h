#pragma once

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "types.h"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define STATS_TYPE_TO_XDP_ACTION(type)       \
  ((type) == STATS_TYPE_ALLOWED   ? XDP_PASS \
   : (type) == STATS_TYPE_PASSED  ? XDP_PASS \
   : (type) == STATS_TYPE_DROPPED ? XDP_DROP \
                                  : XDP_ABORTED)