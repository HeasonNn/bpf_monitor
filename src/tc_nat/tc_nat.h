#ifndef NAT_H
#define NAT_H

#define DEFAULT    0
#define SNAT       1
#define DNAT       2
#define ACTION_MAX (DNAT + 1)

typedef unsigned short __u16;
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct datarec
{
    __u64 rx_packets;
    __u64 rx_bytes;
} __attribute__((aligned(8)));

struct nat_key_t
{
    __u32 ip;
    __u16 port;
    __u8 protocol;
} __attribute__((packed));

struct nat_value_t
{
    __u32 ip;
    __u16 port;
} __attribute__((aligned(2)));
#endif // NAT_H