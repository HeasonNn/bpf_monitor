#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define PATH_MAX 4096

#define BPF_OBJECT_FILE "ebpf_monitor.bpf.o"
#define BPF_OBJECT_XDP_PROG_NAME "xdp_prog"
#define INTERFACE "veth0"

#define PIN_BASE_DIR "/sys/fs/bpf"

#define EXIT_OK 0    //  == EXIT_SUCCESS (stdlib.h) man exit(3)
#define EXIT_FAIL 1  //  == EXIT_FAILURE (stdlib.h) man exit(3)
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#define PIN_DIR_SIZE 512
#define IF_NAMESIZE 16

#define HANDLE_ERR(cond, action, fmt, ...)                             \
  do {                                                                 \
    if (cond) {                                                        \
      fprintf(stderr, fmt " (errno: %d - %s)\n", ##__VA_ARGS__, errno, \
              strerror(errno));                                        \
      action;                                                          \
    }                                                                  \
  } while (0)

#define CHECK_ERR(cond, fmt, ...) HANDLE_ERR(cond, , fmt, ##__VA_ARGS__)

#define CHECK_ERR_CLEANUP(cond, fmt, ...) \
  HANDLE_ERR(cond, goto cleanup, fmt, ##__VA_ARGS__)

#define CHECK_ERR_EXIT(cond, fmt, ...) \
  HANDLE_ERR(cond, exit(1), fmt, ##__VA_ARGS__)

#define CHECK_ERR_EXIT_VAL(cond, val, fmt, ...) \
  HANDLE_ERR(cond, exit(val), fmt, ##__VA_ARGS__)

#define CHECK_ERR_RETURN(cond, fmt, ...) \
  HANDLE_ERR(cond, return, fmt, ##__VA_ARGS__)

#define CHECK_ERR_RETURN_VAL(cond, val, fmt, ...) \
  HANDLE_ERR(cond, return val, fmt, ##__VA_ARGS__)

#define CHECK_ERR_CUSTOM(cond, action, fmt, ...) \
  HANDLE_ERR(cond, action, fmt, ##__VA_ARGS__)

typedef unsigned int __u32;

struct config {
  int ifindex;
  char *ifname;
  char ifname_buf[IF_NAMESIZE];
  __u32 prog_id;
  char pin_dir[PIN_DIR_SIZE];
  char filename[512];
  char progname[32];
};

int open_bpf_map_file(const char *pin_dir, const char *mapname,
                      struct bpf_map_info *info);

int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg);
