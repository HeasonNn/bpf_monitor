/* SPDX-License-Identifier: GPL-2.0 */
#define _POSIX_C_SOURCE 200809L

#include "net_redirect.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <locale.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define EXIT_OK          0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL        1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP    30
#define EXIT_FAIL_BPF    40

#define INTERFACE       "veth-xdp"
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

struct record
{
    __u64 timestamp;
    struct datarec total;
};

struct stats_record
{
    struct record stats[XDP_ACTION_MAX];
};

struct sock_info_t
{
    int sockfd;
    struct sockaddr_in servaddr;
    char buffer[256];
};

static __u64 gettime(void)
{
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0)
    {
        fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
        exit(EXIT_FAIL);
    }
    return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *r, struct record *p)
{
    double period_ = 0;
    __u64 period = 0;

    period = r->timestamp - p->timestamp;
    if (period > 0) period_ = ((double)period / NANOSEC_PER_SEC);

    return period_;
}

static const char *xdp_action_names[XDP_ACTION_MAX] = {
    [XDP_ABORTED] = "XDP_ABORTED",   [XDP_DROP] = "XDP_DROP",
    [XDP_PASS] = "XDP_PASS",         [XDP_TX] = "XDP_TX",
    [XDP_REDIRECT] = "XDP_REDIRECT", [XDP_UNKNOWN] = "XDP_UNKNOWN",
};

const char *action2str(__u32 action)
{
    if (action < XDP_ACTION_MAX) return xdp_action_names[action];
    return NULL;
}

static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
                               struct bpf_map_info *exp)
{
    __u32 info_len = sizeof(*info);
    int err;

    if (map_fd < 0) return EXIT_FAIL;

    err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
    if (err)
    {
        fprintf(stderr, "ERR: %s() can't get info - %s\n", __func__,
                strerror(errno));
        return EXIT_FAIL_BPF;
    }

    if (exp->key_size && exp->key_size != info->key_size)
    {
        fprintf(stderr,
                "ERR: %s() "
                "Map key size(%d) mismatch expected size(%d)\n",
                __func__, info->key_size, exp->key_size);
        return EXIT_FAIL;
    }
    if (exp->value_size && exp->value_size != info->value_size)
    {
        fprintf(stderr,
                "ERR: %s() "
                "Map value size(%d) mismatch expected size(%d)\n",
                __func__, info->value_size, exp->value_size);
        return EXIT_FAIL;
    }
    if (exp->max_entries && exp->max_entries != info->max_entries)
    {
        fprintf(stderr,
                "ERR: %s() "
                "Map max_entries(%d) mismatch expected size(%d)\n",
                __func__, info->max_entries, exp->max_entries);
        return EXIT_FAIL;
    }
    if (exp->type && exp->type != info->type)
    {
        fprintf(stderr,
                "ERR: %s() "
                "Map type(%d) mismatch expected type(%d)\n",
                __func__, info->type, exp->type);
        return EXIT_FAIL;
    }

    return 0;
}

int init_socket(struct sock_info_t *sock_info, const char *ip, int port)
{
    sock_info->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_info->sockfd < 0)
    {
        perror("Socket creation failed");
        return EXIT_FAIL;
    }

    memset(&sock_info->servaddr, 0, sizeof(sock_info->servaddr));
    sock_info->servaddr.sin_family = AF_INET;
    sock_info->servaddr.sin_addr.s_addr = inet_addr(ip);
    sock_info->servaddr.sin_port = htons(port);

    return EXIT_OK;
}

void cleanup_socket(struct sock_info_t *sock_info)
{
    if (sock_info->sockfd >= 0)
    {
        close(sock_info->sockfd);
    }
}

static void stats_print_header()
{
    /* Print stats "header" */
    printf("%-12s\n", "XDP-action");
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev,
                        struct sock_info_t *sock_info)
{
    struct record *rec, *prev;
    double period, pps, mbps;
    __u64 packets, bytes;
    int i;

    stats_print_header();

    for (i = 0; i < XDP_ACTION_MAX; i++)
    {
        char *fmt =
            "%12s %'11lld pkts (%'10.0f pps)"
            " %'11lld Kbytes (%'6.0f Mbits/s)"
            " period:%f\n";
        const char *action = action2str(i);

        rec = &stats_rec->stats[i];
        prev = &stats_prev->stats[i];

        period = calc_period(rec, prev);
        if (period == 0) return;

        packets = rec->total.rx_packets - prev->total.rx_packets;
        pps = packets / period;

        bytes = rec->total.rx_bytes - prev->total.rx_bytes;
        mbps = (bytes * 8) / period / 1000000;

        printf(fmt, action, rec->total.rx_packets, pps,
               rec->total.rx_bytes / 1000, mbps, period);

        snprintf(sock_info->buffer, sizeof(sock_info->buffer),
                 "%'11lld %'10.0f %'11lld %'6.0f", rec->total.rx_packets, pps,
                 rec->total.rx_bytes / 1000, mbps);
        sendto(sock_info->sockfd, sock_info->buffer, strlen(sock_info->buffer),
               0, (const struct sockaddr *)&sock_info->servaddr,
               sizeof(sock_info->servaddr));
    }
}

/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
    if ((bpf_map_lookup_elem(fd, &key, value)) != 0)
    {
        fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
    }
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
    unsigned int nr_cpus = libbpf_num_possible_cpus();
    struct datarec values[nr_cpus];
    __u64 sum_bytes = 0;
    __u64 sum_pkts = 0;
    int i;

    if ((bpf_map_lookup_elem(fd, &key, values)) != 0)
    {
        fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
        return;
    }

    for (i = 0; i < nr_cpus; i++)
    {
        sum_pkts += values[i].rx_packets;
        sum_bytes += values[i].rx_bytes;
    }
    value->rx_packets = sum_pkts;
    value->rx_bytes = sum_bytes;
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
    struct datarec value;

    rec->timestamp = gettime();

    switch (map_type)
    {
        case BPF_MAP_TYPE_ARRAY:
            map_get_value_array(fd, key, &value);
            break;
        case BPF_MAP_TYPE_PERCPU_ARRAY:
            map_get_value_percpu_array(fd, key, &value);
            break;
        default:
            fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
                    map_type);
            return false;
            break;
    }

    rec->total.rx_packets = value.rx_packets;
    rec->total.rx_bytes = value.rx_bytes;
    return true;
}

static void stats_collect(int map_fd, __u32 map_type,
                          struct stats_record *stats_rec)
{
    __u32 key;
    for (key = 0; key < XDP_ACTION_MAX; key++)
    {
        map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
    }
}

static int stats_poll(int map_fd, __u32 map_type, int interval)
{
    struct stats_record prev, record = {0};
    struct sock_info_t sock_info;

    if (init_socket(&sock_info, "127.0.0.1", 9999) == EXIT_FAIL)
    {
        return EXIT_FAIL;
    }

    setlocale(LC_NUMERIC, "en_US");

    stats_collect(map_fd, map_type, &record);
    sleep(1);

    while (1)
    {
        prev = record; /* struct copy */
        stats_collect(map_fd, map_type, &record);
        stats_print(&record, &prev, &sock_info);
        sleep(interval);
    }

    cleanup_socket(&sock_info);
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    struct bpf_map_info map_expect = {0};
    struct bpf_map_info info = {0};
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int stats_map_fd, err, ifindex;
    int interval = 1;

    obj = bpf_object__open_file("net_redirect.bpf.o", NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "Failed to open BPF object file\n");
        goto cleanup;
    }

    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_redirect_func");
    if (!prog)
    {
        fprintf(stderr, "Failed to find eBPF program by name\n");
        goto cleanup;
    }

    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "xdp_stats_map");
    if (stats_map_fd < 0)
    {
        fprintf(stderr, "Failed to get eBPF map {xdp_stats_map}.\n");
        goto cleanup;
    }

    ifindex = if_nametoindex(INTERFACE);
    if (!ifindex)
    {
        fprintf(stderr, "Failed to get interface index for %s\n", INTERFACE);
        goto cleanup;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (!link)
    {
        fprintf(stderr, "Failed to attach BPF program to XDP: %d\n", err);
        goto cleanup;
    }

    map_expect.key_size = sizeof(__u32);
    map_expect.value_size = sizeof(struct datarec);
    map_expect.max_entries = XDP_ACTION_MAX;
    err = __check_map_fd_info(stats_map_fd, &info, &map_expect);
    if (err)
    {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        goto cleanup;
    }

    // dnat_map
    int dnat_map_fd = bpf_object__find_map_fd_by_name(obj, "dnat_map");
    if (dnat_map_fd < 0)
    {
        fprintf(stderr, "Failed to get eBPF map {dnat_map}.\n");
        goto cleanup;
    }

    __u32 dst_ip, nat_dst_ip;

    dst_ip = inet_addr("192.168.50.3");
    nat_dst_ip = inet_addr("172.10.1.2");
    if (bpf_map_update_elem(dnat_map_fd, &dst_ip, &nat_dst_ip, BPF_ANY) != 0)
    {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("dnat map updated successfully.\n");

    // snat_map
    int snat_map_fd = bpf_object__find_map_fd_by_name(obj, "snat_map");
    if (snat_map_fd < 0)
    {
        fprintf(stderr, "Failed to get eBPF map {snat_map}.\n");
        goto cleanup;
    }

    __u32 src_ip, nat_src_ip;

    src_ip = inet_addr("172.10.1.2");
    nat_src_ip = inet_addr("192.168.50.3");
    if (bpf_map_update_elem(snat_map_fd, &src_ip, &nat_src_ip, BPF_ANY) != 0)
    {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("snat map updated successfully.\n");

    // start mainloop
    stats_poll(stats_map_fd, info.type, interval);
    return EXIT_OK;

cleanup:
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    return 0;
}