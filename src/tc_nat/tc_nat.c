/* SPDX-License-Identifier: GPL-2.0 */
#define _POSIX_C_SOURCE 200809L

#include "tc_nat.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <time.h>

#define EXIT_OK          0
#define EXIT_FAIL        1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP    30
#define EXIT_FAIL_BPF    40

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

#define INGRESS_HANDLE 1
#define EGRESS_HANDLE  2

static volatile sig_atomic_t exiting = 0;

struct record
{
    __u64 timestamp;
    struct datarec total;
};

struct stats_record
{
    struct record stats[ACTION_MAX];
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
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0)
    {
        perror("Error with clock_gettime");
        exit(EXIT_FAIL);
    }
    return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *r, struct record *p)
{
    __u64 period = r->timestamp - p->timestamp;
    return (period > 0) ? ((double)period / NANOSEC_PER_SEC) : 0;
}

static const char *action_names[ACTION_MAX] = {
    [DEFAULT] = "DEFAULT",
    [SNAT] = "SNAT",
    [DNAT] = "DNAT",
};

const char *action2str(__u32 action)
{
    return (action < ACTION_MAX) ? action_names[action] : NULL;
}

static int check_map_fd_info(int map_fd, struct bpf_map_info *info,
                             struct bpf_map_info *exp)
{
    __u32 info_len = sizeof(*info);
    if (map_fd < 0) return EXIT_FAIL;

    if (bpf_obj_get_info_by_fd(map_fd, info, &info_len))
    {
        perror("Can't get map info");
        return EXIT_FAIL_BPF;
    }

    if ((exp->key_size && exp->key_size != info->key_size) ||
        (exp->value_size && exp->value_size != info->value_size) ||
        (exp->max_entries && exp->max_entries != info->max_entries) ||
        (exp->type && exp->type != info->type))
    {
        fprintf(stderr, "Map properties mismatch\n");
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
    if (sock_info->sockfd >= 0) close(sock_info->sockfd);
}

static void stats_print_header() { printf("%-12s\n", "action"); }

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev,
                        struct sock_info_t *sock_info)
{
    struct record *rec, *prev;
    double period, pps, mbps;
    __u64 packets, bytes;

    stats_print_header();

    for (int i = 0; i < ACTION_MAX; i++)
    {
        const char *action = action2str(i);
        char *fmt =
            "%12s %'11lld pkts (%'10.0f pps)"
            " %'11lld Kbytes (%'6.0f Mbits/s)"
            " period:%f\n";

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
    if (bpf_map_lookup_elem(fd, &key, value) != 0)
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

    if (bpf_map_lookup_elem(fd, &key, values) != 0)
    {
        fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
        return;
    }

    for (unsigned int i = 0; i < nr_cpus; i++)
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

    rec->total = value;
    return true;
}

static void stats_collect(int fd, __u32 map_type,
                          struct stats_record *stats_rec)
{
    for (__u32 key = 0; key < ACTION_MAX; key++)
    {
        map_collect(fd, map_type, key, &stats_rec->stats[key]);
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

    stats_collect(map_fd, map_type, &record);
    sleep(1);

    while (!exiting)
    {
        prev = record;
        stats_collect(map_fd, map_type, &record);
        stats_print(&record, &prev, &sock_info);
        sleep(interval);
    }

    cleanup_socket(&sock_info);
    return EXIT_OK;
}

int tc_cmd_add_clsact(const char *ifname)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", ifname);
    int ret = system(cmd);
    if (ret != 0 &&
        WEXITSTATUS(ret) != 1)  // Allow exit status 1 for existing clsact
    {
        snprintf(cmd, sizeof(cmd), "tc qdisc show dev %s | grep clsact",
                 ifname);
        ret = system(cmd);
        if (ret != 0)  // clsact does not exist
        {
            return -1;
        }
    }
    return 0;
}

int update_nat_map(const char *map_name, struct bpf_object *obj,
                   const char *src_ip, __u16 src_port, __u8 protocol,
                   const char *dst_ip, __u16 dst_port)
{
    int map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
    if (map_fd < 0)
    {
        fprintf(stderr, "Failed to get eBPF map {%s}.\n", map_name);
        return EXIT_FAIL;
    }

    struct nat_key_t key = {
        .ip = inet_addr(src_ip),
        .port = htons(src_port),
        .protocol = protocol,
    };

    struct nat_value_t value = {
        .ip = inet_addr(dst_ip),
        .port = htons(dst_port),
    };

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0)
    {
        perror("bpf_map_update_elem");
        return EXIT_FAIL;
    }

    printf("NAT map {%s} updated successfully: %s:%u -> %s:%u (protocol: %u)\n",
           map_name, src_ip, src_port, dst_ip, dst_port, protocol);
    return EXIT_OK;
}

void cleanup_tc_hook(struct bpf_tc_hook *tc_hook, struct bpf_tc_opts *tc_opts,
                     bool hook_created)
{
    if (hook_created)
    {
        int err = bpf_tc_detach(tc_hook, tc_opts);
        if (err)
        {
            fprintf(stderr, "Failed to detach TC hook: %d\n", err);
        }
        else
        {
            printf("Detached TC hook\n");
        }
        bpf_tc_hook_destroy(tc_hook);
        memset(tc_opts, 0, sizeof(*tc_opts));  // Clean up tc_opts as well
    }
}

static void sig_int(int signo)
{
    exiting = 1;
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) 
    {
        printf("Usage: ./tc_nat [dev_name] \n");
        printf("eg:    ./tc_nat ens34 \n");
        return EXIT_FAIL;
    }
    
    char *dev_name = argv[1];
    struct bpf_object *obj;
    int stats_map_fd, err = 0, ifindex;
    int interval = 1;
    bool ig_hook_created = false, eg_hook_created = false;

    struct bpf_map_info map_expect = {0};
    struct bpf_map_info info = {0};

    if (signal(SIGINT, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        return EXIT_FAIL;
    }

    obj = bpf_object__open_file("tc_nat.bpf.o", NULL);
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

    ifindex = if_nametoindex(dev_name);

    err = tc_cmd_add_clsact(dev_name);
    if (err && err != -EEXIST)
    {
        fprintf(stderr, "Failed to add clsact qdisc: %d\n", err);
        goto cleanup;
    }

    // Add DNAT program
    struct bpf_program *tc_dnat_prog =
        bpf_object__find_program_by_name(obj, "tc_dnat_func");
    if (!tc_dnat_prog)
    {
        fprintf(stderr, "Failed to find eBPF program 'tc_dnat_func'\n");
        goto cleanup;
    }

    int tc_dnat_prog_fd = bpf_program__fd(tc_dnat_prog);
    if (tc_dnat_prog_fd < 0)
    {
        fprintf(stderr, "Failed to get fd for 'tc_dnat_func'\n");
        goto cleanup;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_ig_hook, .ifindex = ifindex,
                        .attach_point = BPF_TC_INGRESS);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_ig_opts, .handle = INGRESS_HANDLE,
                        .priority = 1, .prog_fd = tc_dnat_prog_fd);

    if ((err = bpf_tc_hook_create(&tc_ig_hook)) && err != -EEXIST)
    {
        fprintf(stderr, "Failed to create ingress TC hook: %d\n", err);
        goto cleanup;
    }
    ig_hook_created = true;
    if ((err = bpf_tc_attach(&tc_ig_hook, &tc_ig_opts)))
    {
        fprintf(stderr, "Failed to attach ingress TC: %d\n", err);
        goto cleanup;
    }

    // Add SNAT program
    struct bpf_program *tc_snat_prog =
        bpf_object__find_program_by_name(obj, "tc_snat_func");
    if (!tc_snat_prog)
    {
        fprintf(stderr, "Failed to find eBPF program 'tc_snat_func'\n");
        goto cleanup;
    }

    int tc_snat_prog_fd = bpf_program__fd(tc_snat_prog);
    if (tc_snat_prog_fd < 0)
    {
        fprintf(stderr, "Failed to get fd for 'tc_snat_func'\n");
        goto cleanup;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_eg_hook, .ifindex = ifindex,
                        .attach_point = BPF_TC_EGRESS);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_eg_opts, .handle = EGRESS_HANDLE,
                        .priority = 1, .prog_fd = tc_snat_prog_fd);

    if ((err = bpf_tc_hook_create(&tc_eg_hook)) && err != -EEXIST)
    {
        fprintf(stderr, "Failed to create egress TC hook: %d\n", err);
        goto cleanup;
    }
    eg_hook_created = true;

    if ((err = bpf_tc_attach(&tc_eg_hook, &tc_eg_opts)))
    {
        fprintf(stderr, "Failed to attach egress TC: %d\n", err);
        goto cleanup;
    }

    printf("Successfully attached ingress and egress TC hooks to %s\n",
           dev_name);

    if ((err = update_nat_map("dnat_map", obj, "10.177.53.174", 80, IPPROTO_TCP,
                              "172.200.42.80", 9050)) < 0)
        goto cleanup;

    if ((err = update_nat_map("snat_map", obj, "172.200.42.80", 9050, IPPROTO_TCP,
                              "10.177.53.174", 80)) < 0)
        goto cleanup;

    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "tc_stats_map");
    if (stats_map_fd < 0)
    {
        fprintf(stderr, "Failed to get eBPF map {xdp_stats_map}.\n");
        goto cleanup;
    }

    map_expect.key_size = sizeof(__u32);
    map_expect.value_size = sizeof(struct datarec);
    map_expect.max_entries = ACTION_MAX;
    if ((err = check_map_fd_info(stats_map_fd, &info, &map_expect)))
    {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        goto cleanup;
    }

    // Start main loop
    stats_poll(stats_map_fd, info.type, interval);

    printf("Received interrupt signal, cleaning up...\n");

cleanup:
    cleanup_tc_hook(&tc_ig_hook, &tc_ig_opts, ig_hook_created);
    cleanup_tc_hook(&tc_eg_hook, &tc_eg_opts, eg_hook_created);

    if (obj)
    {
        bpf_object__close(obj);
        printf("Closed BPF object\n");
    }

    return err < 0 ? EXIT_FAIL : EXIT_OK;
}