#include <net/if.h>

#include "prog_loader.h"
#include "prog_stats.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: ./ebpf_monitor [dev_name] \n");
    printf("eg:    ./ebpf_monitor veth0 \n");
    return 0;
  }

  int len;
  // char *ifname = argv[1];
  char *ifname = INTERFACE;

  int ifindex = if_nametoindex(ifname);
  CHECK_ERR_EXIT(!ifindex, "Error: Failed to get interface index for %s",
                 ifname);

  struct config cfg = {
      .ifname = ifname,
      .ifindex = ifindex,
  };

  strncpy(cfg.filename, BPF_OBJECT_FILE, sizeof(cfg.filename));
  strncpy(cfg.progname, BPF_OBJECT_XDP_PROG_NAME, sizeof(cfg.progname));

  len = snprintf(cfg.pin_dir, PIN_DIR_SIZE, "%s/%s", PIN_BASE_DIR, cfg.ifname);
  CHECK_ERR_RETURN_VAL(len < 0, EXIT_FAIL_OPTION,
                       "Error: creating pin dirname");

  ebpf_prog_loader(&cfg);
  ebpf_prog_stats(&cfg);
  return 0;
}