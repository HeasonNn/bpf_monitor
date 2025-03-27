#include "prog_helper.h"

static int remove_pinned_maps(const char pin_dir[PIN_DIR_SIZE]) {
  DIR *dir = opendir(pin_dir);
  if (!dir) {
    perror("opendir");
    return -1;
  }

  struct dirent *entry;
  char filepath[PATH_MAX];

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    if (strlen(pin_dir) + strlen(entry->d_name) + 2 > sizeof(filepath)) {
      fprintf(stderr, "Warning: filepath too long: %s/%s\n", pin_dir,
              entry->d_name);
      continue;
    }

    // 安全拼接路径
    snprintf(filepath, sizeof(filepath), "%s/%s", pin_dir, entry->d_name);

    // 删除文件
    if (unlink(filepath) < 0) {
      perror("unlink");
      closedir(dir);
      return -1;
    }
  }

  closedir(dir);
  return 0;
}

int open_bpf_map_file(const char *pin_dir, const char *mapname,
                      struct bpf_map_info *info) {
  char filename[PATH_MAX];
  int err, len, fd;
  __u32 info_len = sizeof(*info);

  len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
  CHECK_ERR_RETURN_VAL(len < 0, -1, "Error: constructing full mapname path");

  fd = bpf_obj_get(filename);
  CHECK_ERR_RETURN_VAL(fd < 0, fd, "WARN: Failed to open bpf map file:%s",
                       filename);

  if (info) {
    err = bpf_obj_get_info_by_fd(fd, info, &info_len);
    CHECK_ERR_RETURN_VAL(err, EXIT_FAIL_BPF, "Error: %s() can't get info",
                         __func__);
  }

  return fd;
}

int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg) {
  int err;

  if (access(cfg->pin_dir, F_OK) != -1) {
    err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
    CHECK_ERR_RETURN_VAL(err, EXIT_FAIL_OPTION, "Error: UNpinning maps in %s",
                         cfg->pin_dir);

    err = remove_pinned_maps(cfg->pin_dir);
    CHECK_ERR_RETURN_VAL(err, EXIT_FAIL_OPTION,
                         "Error: removing pinned maps in %s", cfg->pin_dir);
    printf("Finished removed. \n");
  }

  err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
  CHECK_ERR_RETURN_VAL(err, EXIT_FAIL_BPF, "Error: Pinning maps in %s",
                       cfg->pin_dir);

  return 0;
}