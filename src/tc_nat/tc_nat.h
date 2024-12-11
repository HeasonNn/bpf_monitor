#pragma once

typedef long long unsigned int __u64;

#define DEFAULT    0
#define SNAT       1
#define DNAT       2
#define ACTION_MAX DNAT + 1

struct datarec
{
    __u64 rx_packets;
    __u64 rx_bytes;
};
