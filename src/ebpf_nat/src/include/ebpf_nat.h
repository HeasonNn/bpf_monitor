#ifndef EBPF_NAT_H
#define EBPF_NAT_H

#include "../include/macros.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT    0
#define SNAT       1
#define DNAT       2
#define ACTION_MAX (DNAT + 1)

#define NANOSEC_PER_SEC 1000000000

#define INGRESS_HANDLE 1
#define EGRESS_HANDLE  2

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

struct record
{
    __u64 timestamp;
    struct datarec total;
};

struct stats_record
{
    struct record stats[ACTION_MAX];
};

typedef struct
{
    struct stats_record prev;
    struct stats_record record;
    int map_fd;
    __u32 map_type;
    int initialized;
} stats_context_t;

extern volatile sig_atomic_t exiting;

__u64 stats_get_current_time(void);
double stats_calc_period(struct record *r, struct record *p);
const char *stats_action2str(__u32 action);
bool stats_map_collect(int fd, __u32 map_type, __u32 key, struct record *rec);
void stats_collect(int fd, __u32 map_type, struct stats_record *stats_rec);
int stats_poll_init(stats_context_t *ctx);
int stats_poll_step(stats_context_t *ctx);
int stats_poll(int map_fd, __u32 map_type, int interval);
void stats_print_header();
void stats_print(struct stats_record *stats_rec,
                 struct stats_record *stats_prev);

int bpf_load_object(struct bpf_object **obj, const char *file);
int bpf_validate_map(struct bpf_object *obj, const char *map_name);
int bpf_validate_map_info(int map_fd, struct bpf_map_info *info,
                          struct bpf_map_info *exp);
void bpf_map_get_value_array(int fd, __u32 key, struct datarec *value);
void bpf_map_get_value_percpu_array(int fd, __u32 key, struct datarec *value);

int net_update_nat_map(const char *map_name, struct bpf_object *obj,
                       const char *src_ip, __u16 src_port, __u8 protocol,
                       const char *dst_ip, __u16 dst_port);
int net_add_clsact_qdisc(const char *ifname);
int net_update_nat_mapping_if_needed(struct bpf_object *obj);

void cleanup_tc_hook();
int init_ebpf_nat(const char *dev_name);

#endif