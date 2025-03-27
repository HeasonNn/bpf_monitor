#define _POSIX_C_SOURCE 200809L

#include "prog_stats.h"

struct record {
  __u64 timestamp;
  struct datarec total;
};

struct stats_record {
  struct record stats[STATS_TYPE_MAX];
};

__u64 gettime(void) {
  struct timespec t;
  CHECK_ERR_EXIT(clock_gettime(CLOCK_MONOTONIC, &t) < 0,
                 "ERROR: error with gettimeofday.");

  return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *r, struct record *p) {
  double period_ = 0;
  __u64 period = 0;

  period = r->timestamp - p->timestamp;
  if (period > 0) period_ = ((double)period / NANOSEC_PER_SEC);

  return period_;
}

const char *get_stats_type(int i) {
  switch (i) {
    case STATS_TYPE_ALLOWED:
      return "Allowed";
    case STATS_TYPE_BLOCK:
      return "Block";
    case STATS_TYPE_PASSED:
      return "Passed";
    case STATS_TYPE_DROPPED:
      return "Dropped";
    default:
      return "Dropped";
  }
}

static void stats_print_header() {
  /* Print stats "header" */
  printf("%-12s\n", "Action");
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev) {
  struct record *rec, *prev;
  double period, pps, mbps;
  __u64 packets, bytes;
  int i;

  stats_print_header();

  for (i = 0; i < STATS_TYPE_MAX; i++) {
    char *fmt =
        "%12s %'11lld pkts (%'10.0f pps)"
        " %'11lld Kbytes (%'6.0f Mbits/s)"
        " period:%f\n";
    const char *action = get_stats_type(i);

    rec = &stats_rec->stats[i];
    prev = &stats_prev->stats[i];

    period = calc_period(rec, prev);
    if (period == 0) return;

    packets = rec->total.rx_packets - prev->total.rx_packets;
    pps = packets / period;

    bytes = rec->total.rx_bytes - prev->total.rx_bytes;
    mbps = (bytes * 8) / period / 1000000;

    printf(fmt, action, rec->total.rx_packets, pps, rec->total.rx_bytes / 1000,
           mbps, period);
  }
}

void map_get_value_array(int fd, __u32 key, struct datarec *value) {
  if (bpf_map_lookup_elem(fd, &key, value) != 0) {
    fprintf(stderr, "Error: bpf_map_lookup_elem failed key:0x%X (%d - %s)\n",
            key, errno, strerror(errno));
    return;
  }
}

void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value) {
  unsigned int nr_cpus = libbpf_num_possible_cpus();
  struct datarec values[nr_cpus];
  __u64 sum_bytes = 0;
  __u64 sum_pkts = 0;

  if (bpf_map_lookup_elem(fd, &key, values) != 0) {
    fprintf(stderr, "Error: bpf_map_lookup_elem failed key:0x%X (%d - %s)\n",
            key, errno, strerror(errno));
    return;
  }

  for (unsigned i = 0; i < nr_cpus; i++) {
    sum_pkts += values[i].rx_packets;
    sum_bytes += values[i].rx_bytes;
  }
  value->rx_packets = sum_pkts;
  value->rx_bytes = sum_bytes;
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec) {
  struct datarec value;

  rec->timestamp = gettime();

  switch (map_type) {
    case BPF_MAP_TYPE_ARRAY:
      map_get_value_array(fd, key, &value);
      break;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
      map_get_value_percpu_array(fd, key, &value);
      break;
    default:
      fprintf(stderr, "Error: Unknown map_type(%u) cannot handle\n", map_type);
      return false;
      break;
  }

  rec->total.rx_packets = value.rx_packets;
  rec->total.rx_bytes = value.rx_bytes;
  return true;
}

void stats_collect(int fd, __u32 map_type, struct stats_record *stats_rec) {
  for (__u32 key = 0; key < 4; key++) {
    map_collect(fd, map_type, key, &stats_rec->stats[key]);
  }
}

static int ebpf_stats_poll(int fd, __u32 map_type, unsigned interval) {
  struct stats_record prev, record = {0};

  stats_collect(fd, map_type, &record);
  sleep(1);

  while (1) {
    prev = record;
    stats_collect(fd, map_type, &record);
    stats_print(&record, &prev);
    sleep(interval);
  }

  return 0;
}

static int check_map_fd_info(int map_fd, struct bpf_map_info *info,
                             struct bpf_map_info *exp) {
  __u32 info_len = sizeof(*info);
  int err;

  if (map_fd < 0) return 1;

  err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
  if (err) {
    fprintf(stderr, "ERR: %s() can't get info - %s\n", __func__,
            strerror(errno));
    return 40;
  }

  if (exp->key_size && exp->key_size != info->key_size) {
    fprintf(stderr,
            "ERR: %s() "
            "Map key size(%d) mismatch expected size(%d)\n",
            __func__, info->key_size, exp->key_size);
    return 1;
  }
  if (exp->value_size && exp->value_size != info->value_size) {
    fprintf(stderr,
            "ERR: %s() "
            "Map value size(%d) mismatch expected size(%d)\n",
            __func__, info->value_size, exp->value_size);
    return 1;
  }
  if (exp->max_entries && exp->max_entries != info->max_entries) {
    fprintf(stderr,
            "ERR: %s() "
            "Map max_entries(%d) mismatch expected size(%d)\n",
            __func__, info->max_entries, exp->max_entries);
    return 1;
  }
  if (exp->type && exp->type != info->type) {
    fprintf(stderr,
            "ERR: %s() "
            "Map type(%d) mismatch expected type(%d)\n",
            __func__, info->type, exp->type);
    return 1;
  }

  return 0;
}

int ebpf_prog_stats(struct config *cfg) {
  int err;
  int interval = 2;

  struct bpf_map_info map_expect = {0};
  struct bpf_map_info info = {0};

  map_expect.key_size = sizeof(__u32);
  map_expect.value_size = sizeof(struct datarec);
  map_expect.max_entries = STATS_TYPE_MAX;

  int stats_map_fd = open_bpf_map_file(cfg->pin_dir, "xdp_stats_map", &info);
  CHECK_ERR(stats_map_fd < 0, "Error: Failed to get eBPF map");

  err = check_map_fd_info(stats_map_fd, &info, &map_expect);
  CHECK_ERR(err, "Error: map via FD not compatible");

  ebpf_stats_poll(stats_map_fd, info.type, interval);

  return 0;
}