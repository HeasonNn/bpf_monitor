#define _POSIX_C_SOURCE 200809L

#include "prog_loader.h"

int ebpf_prog_loader(struct config *cfg) {
  int prog_fd = -1;
  int err;

  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
  DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

  xdp_opts.open_filename = cfg->filename;
  xdp_opts.prog_name = cfg->progname;
  xdp_opts.opts = &opts;

  struct xdp_program *prog = xdp_program__create(&xdp_opts);
  err = libxdp_get_error(prog);
  if (err) {
    char errmsg[1024];
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    fprintf(stderr, "Error: loading program: %s\n", errmsg);
    exit(EXIT_FAIL_BPF);
  }

  err = xdp_program__attach(prog, cfg->ifindex, XDP_MODE_NATIVE, 0);
  CHECK_ERR_EXIT_VAL(err, err, "Error: xdp_program__attach failed");

  err = pin_maps_in_bpf_object(xdp_program__bpf_obj(prog), cfg);
  CHECK_ERR_EXIT_VAL(err, err, "Error: pin_maps_in_bpf_object failed");

  prog_fd = xdp_program__fd(prog);
  CHECK_ERR_EXIT_VAL(prog_fd < 0, EXIT_FAIL_BPF,
                     "Error: xdp_program__fd failed");

  printf("Successfully load XDP program.\n");
  return prog_fd;
}