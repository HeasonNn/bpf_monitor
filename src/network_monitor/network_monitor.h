#pragma once

#define EXIT_OK          0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL        1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP    30
#define EXIT_FAIL_BPF    40

typedef long long unsigned int __u64;

/* This is the data record stored in the map */
struct datarec
{
    __u64 rx_packets;
    __u64 rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif