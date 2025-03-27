/* SPDX-License-Identifier: GPL-2.0 */
#define _POSIX_C_SOURCE 200809L

#include "../include/ebpf_nat.h"

#define DECLARE_LIBBPF_OPTS_LOCAL(TYPE, VAR, ...) \
  do {                                            \
    memset(&(VAR), 0, sizeof(struct TYPE));       \
    (VAR).sz = sizeof(struct TYPE);               \
    __VA_ARGS__;                                  \
  } while (0)

volatile sig_atomic_t exiting = 0;

static bool ig_hook_created = 0, eg_hook_created = 0;
struct bpf_tc_hook tc_ig_hook, tc_eg_hook;
struct bpf_tc_opts tc_ig_opts, tc_eg_opts;
struct bpf_object *obj;

const char *action_names[ACTION_MAX] = {
    [DEFAULT] = "DEFAULT",
    [SNAT] = "SNAT",
    [DNAT] = "DNAT",
};

__u64 stats_get_current_time(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) < 0) {
    perror("Error with clock_gettime");
    exit(EXIT_FAIL);
  }
  return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

double stats_calc_period(struct record *r, struct record *p) {
  __u64 period = r->timestamp - p->timestamp;
  return (period > 0) ? ((double)period / NANOSEC_PER_SEC) : 0;
}

const char *stats_action2str(__u32 action) {
  return (action < ACTION_MAX) ? action_names[action] : NULL;
}

bool stats_map_collect(int fd, __u32 map_type, __u32 key, struct record *rec) {
  struct datarec value;

  rec->timestamp = stats_get_current_time();

  switch (map_type) {
    case BPF_MAP_TYPE_ARRAY:
      bpf_map_get_value_array(fd, key, &value);
      break;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
      bpf_map_get_value_percpu_array(fd, key, &value);
      break;
    default:
      fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n", map_type);
      return false;
      break;
  }

  rec->total = value;
  return true;
}

void stats_collect(int fd, __u32 map_type, struct stats_record *stats_rec) {
  for (__u32 key = 0; key < ACTION_MAX; key++) {
    stats_map_collect(fd, map_type, key, &stats_rec->stats[key]);
  }
}

int stats_poll_init(stats_context_t *ctx) {
  struct bpf_map_info info = {0};

  int stats_map_fd = bpf_object__find_map_fd_by_name(obj, "ebpf_stats_map");
  if (stats_map_fd < 0) {
    fprintf(stderr, "Failed to get eBPF map {ebpf_stats_map}.\n");
    cleanup_tc_hook();
    return EXIT_FAIL;
  }

  if (bpf_validate_map_info(stats_map_fd, &info,
                            &(struct bpf_map_info){
                                .key_size = sizeof(__u32),
                                .value_size = sizeof(struct datarec),
                                .max_entries = ACTION_MAX,
                            })) {
    cleanup_tc_hook();
    return EXIT_FAIL;
  }

  ctx->map_fd = stats_map_fd;
  ctx->map_type = info.type;
  ctx->initialized = 0;
  return EXIT_OK;
}

int stats_poll_step(stats_context_t *ctx) {
  if (!ctx->initialized) {
    stats_collect(ctx->map_fd, ctx->map_type, &ctx->record);
    ctx->initialized = 1;
    return EXIT_OK;
  }

  ctx->prev = ctx->record;
  stats_collect(ctx->map_fd, ctx->map_type, &ctx->record);

  stats_print(&ctx->record, &ctx->prev);

  return EXIT_OK;
}

int stats_poll(int map_fd, __u32 map_type, int interval) {
  struct stats_record prev, record = {0};

  stats_collect(map_fd, map_type, &record);
  sleep(1);

  while (!exiting) {
    prev = record;
    stats_collect(map_fd, map_type, &record);
    stats_print(&record, &prev);
    sleep(interval);
  }

  return EXIT_OK;
}

void stats_print_header() { printf("%-12s\n", "action"); };

void stats_print(struct stats_record *stats_rec,
                 struct stats_record *stats_prev) {
  struct record *rec, *prev;
  double period, pps, mbps;
  __u64 packets, bytes;

  stats_print_header();

  for (int i = 0; i < ACTION_MAX; i++) {
    const char *action = stats_action2str(i);
    char *fmt =
        "%12s %'11lld pkts (%'10.0f pps)"
        " %'11lld Kbytes (%'6.0f Mbits/s)"
        " period:%f\n";

    rec = &stats_rec->stats[i];
    prev = &stats_prev->stats[i];

    period = stats_calc_period(rec, prev);
    if (period == 0) return;

    packets = rec->total.rx_packets - prev->total.rx_packets;
    pps = packets / period;

    bytes = rec->total.rx_bytes - prev->total.rx_bytes;
    mbps = (bytes * 8) / period / 1000000;

    printf(fmt, action, rec->total.rx_packets, pps, rec->total.rx_bytes / 1000,
           mbps, period);
  }
}

int bpf_load_object(struct bpf_object **obj, const char *file) {
  int err = 0;

  *obj = bpf_object__open_file(file, NULL);
  if (libbpf_get_error(*obj)) {
    fprintf(stderr, "Failed to open BPF object file\n");
    return EXIT_FAIL;
  }

  err = bpf_object__load(*obj);
  if (err) {
    fprintf(stderr, "Failed to load BPF object: %d\n", err);
    return EXIT_FAIL;
  }
  return EXIT_OK;
}

int bpf_validate_map(struct bpf_object *obj, const char *map_name) {
  int stats_map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
  if (stats_map_fd < 0) {
    fprintf(stderr, "Failed to get eBPF map {%s}.\n", map_name);
    return EXIT_FAIL;
  }

  struct bpf_map_info map_expect = {0};
  struct bpf_map_info info = {0};

  map_expect.key_size = sizeof(__u32);
  map_expect.value_size = sizeof(struct datarec);
  map_expect.max_entries = ACTION_MAX;

  return bpf_validate_map_info(stats_map_fd, &info, &map_expect);
}

int bpf_validate_map_info(int map_fd, struct bpf_map_info *info,
                          struct bpf_map_info *exp) {
  __u32 info_len = sizeof(*info);
  if (map_fd < 0) return EXIT_FAIL;

  if (bpf_obj_get_info_by_fd(map_fd, info, &info_len)) {
    perror("Can't get map info");
    return EXIT_FAIL_BPF;
  }

  if ((exp->key_size && exp->key_size != info->key_size) ||
      (exp->value_size && exp->value_size != info->value_size) ||
      (exp->max_entries && exp->max_entries != info->max_entries) ||
      (exp->type && exp->type != info->type)) {
    fprintf(stderr, "Map properties mismatch\n");
    return EXIT_FAIL;
  }

  return 0;
}

void bpf_map_get_value_array(int fd, __u32 key, struct datarec *value) {
  if (bpf_map_lookup_elem(fd, &key, value) != 0) {
    fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
  }
}

void bpf_map_get_value_percpu_array(int fd, __u32 key, struct datarec *value) {
  unsigned int nr_cpus = libbpf_num_possible_cpus();
  struct datarec values[nr_cpus];
  __u64 sum_bytes = 0;
  __u64 sum_pkts = 0;

  if (bpf_map_lookup_elem(fd, &key, values) != 0) {
    fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
    return;
  }

  for (unsigned int i = 0; i < nr_cpus; i++) {
    sum_pkts += values[i].rx_packets;
    sum_bytes += values[i].rx_bytes;
  }
  value->rx_packets = sum_pkts;
  value->rx_bytes = sum_bytes;
}

int net_update_nat_map(const char *map_name, struct bpf_object *obj,
                       const char *src_ip, __u16 src_port, __u8 protocol,
                       const char *dst_ip, __u16 dst_port) {
  int map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
  if (map_fd < 0) {
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

  if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
    perror("bpf_map_update_elem");
    return EXIT_FAIL;
  }

  printf("NAT map {%s} updated successfully: %s:%u -> %s:%u (protocol: %u)\n",
         map_name, src_ip, src_port, dst_ip, dst_port, protocol);
  return EXIT_OK;
}

int net_add_clsact_qdisc(const char *ifname) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", ifname);
  int ret = system(cmd);
  if (ret != 0 && WEXITSTATUS(ret) != 1) {
    snprintf(cmd, sizeof(cmd), "tc qdisc show dev %s | grep clsact", ifname);
    ret = system(cmd);
    if (ret != 0) {
      return -1;
    }
  }
  return 0;
}

int net_update_nat_mapping_if_needed(struct bpf_object *obj) {
  int err = 0;

  err = net_update_nat_map("dnat_map", obj, "10.177.53.174", 80, IPPROTO_TCP,
                           "172.200.42.80", 9050);
  if (err < 0) {
    return EXIT_FAIL;
  }

  err = net_update_nat_map("snat_map", obj, "172.200.42.80", 9050, IPPROTO_TCP,
                           "10.177.53.174", 80);
  return err < 0 ? EXIT_FAIL : EXIT_OK;
}

void cleanup_tc_hook() {
  int err = 0;
  printf("Cleaning up...\n");

  if (ig_hook_created) {
    err = bpf_tc_detach(&tc_ig_hook, &tc_ig_opts);
    if (err < 0 && err != -ENOENT) {
      fprintf(stderr, "Failed to detach ingress TC hook\n");
    }

    bpf_tc_hook_destroy(&tc_ig_hook);
    memset(&tc_ig_opts, 0, sizeof(tc_ig_opts));
  }

  if (eg_hook_created) {
    err = bpf_tc_detach(&tc_eg_hook, &tc_eg_opts);
    if (err < 0 && err != -ENOENT) {
      fprintf(stderr, "Failed to detach egress TC hook\n");
    }

    bpf_tc_hook_destroy(&tc_eg_hook);
    memset(&tc_eg_opts, 0, sizeof(tc_eg_opts));
  }

  if (obj) {
    bpf_object__close(obj);
    printf("Closed BPF object\n");
    obj = NULL;
  }
}

int init_ebpf_nat(const char *dev_name) {
  int err = 0, ifindex;

  ifindex = if_nametoindex(dev_name);
  if (ifindex == 0) {
    fprintf(stderr, "Failed to get interface index for %s.\n", dev_name);
    return EXIT_FAIL;
  }

  if (bpf_load_object(&obj, "ebpf_nat.bpf.o")) return EXIT_FAIL;

  struct bpf_program *ebpf_dnat_prog =
      bpf_object__find_program_by_name(obj, "ebpf_dnat_func");
  if (!ebpf_dnat_prog) {
    fprintf(stderr, "Failed to find eBPF program 'ebpf_dnat_func'\n");
    return EXIT_FAIL;
  }

  int ebpf_dnat_prog_fd = bpf_program__fd(ebpf_dnat_prog);
  if (ebpf_dnat_prog_fd < 0) {
    fprintf(stderr, "Failed to get fd for 'tc_dnat_func'\n");
    return EXIT_FAIL;
  }

  DECLARE_LIBBPF_OPTS_LOCAL(bpf_tc_hook, tc_ig_hook,
                            tc_ig_hook.ifindex = ifindex,
                            tc_ig_hook.attach_point = BPF_TC_INGRESS);
  DECLARE_LIBBPF_OPTS_LOCAL(
      bpf_tc_opts, tc_ig_opts, tc_ig_opts.handle = INGRESS_HANDLE,
      tc_ig_opts.priority = 1, tc_ig_opts.prog_fd = ebpf_dnat_prog_fd);

  if ((err = bpf_tc_hook_create(&tc_ig_hook)) && err != -EEXIST) {
    fprintf(stderr, "Failed to create ingress TC hook: %d\n", err);
    return EXIT_FAIL;
  }
  ig_hook_created = true;

  printf("Create TC Ingress hook...\n");

  if ((err = bpf_tc_attach(&tc_ig_hook, &tc_ig_opts))) {
    fprintf(stderr, "Failed to attach ingress TC: %d\n", err);
    return EXIT_FAIL;
  }

  printf("Attach TC Ingress hook...\n");

  struct bpf_program *ebpf_snat_prog =
      bpf_object__find_program_by_name(obj, "ebpf_snat_func");
  if (!ebpf_snat_prog) {
    fprintf(stderr, "Failed to find eBPF program 'ebpf_snat_func'\n");
    return EXIT_FAIL;
  }

  int ebpf_snat_prog_fd = bpf_program__fd(ebpf_snat_prog);
  if (ebpf_snat_prog_fd < 0) {
    fprintf(stderr, "Failed to get fd for 'ebpf_snat_prog_fd'\n");
    return EXIT_FAIL;
  }

  DECLARE_LIBBPF_OPTS_LOCAL(bpf_tc_hook, tc_eg_hook,
                            tc_eg_hook.ifindex = ifindex,
                            tc_eg_hook.attach_point = BPF_TC_EGRESS);
  DECLARE_LIBBPF_OPTS_LOCAL(
      bpf_tc_opts, tc_eg_opts, tc_eg_opts.handle = EGRESS_HANDLE,
      tc_eg_opts.priority = 1, tc_eg_opts.prog_fd = ebpf_snat_prog_fd);

  if ((err = bpf_tc_hook_create(&tc_eg_hook)) && err != -EEXIST) {
    fprintf(stderr, "Failed to create egress TC hook: %d\n", err);
    return EXIT_FAIL;
  }
  eg_hook_created = true;

  printf("Create TC Egress hook...\n");

  if ((err = bpf_tc_attach(&tc_eg_hook, &tc_eg_opts))) {
    fprintf(stderr, "Failed to attach egress TC: %d\n", err);
    return EXIT_FAIL;
  }

  printf("Attacg TC Egress hook...\n");

  printf("Successfully attached ingress and egress TC hooks\n");

  if (net_update_nat_mapping_if_needed(obj)) {
    cleanup_tc_hook();
    return EXIT_FAIL;
  }

  return EXIT_OK;
}