#include "rule_helper.h"

// 五元组结构
struct five_tuple {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 proto;
} __attribute__((packed));

// CIDR 前缀结构
struct lpm_key {
  __u32 prefixlen;
  __u32 ip;
};

// ✅ 创建 rule_manager_t 实例，初始化 XDP maps
rule_manager_t *create_rule_manager(char *pin_dir) {
  // char pin_dir[512];
  // snprintf(pin_dir, sizeof(pin_dir), "%s/%s", PIN_BASE_DIR, INTERFACE);

  rule_manager_t *manager = (rule_manager_t *)malloc(sizeof(rule_manager_t));
  if (!manager) {
    fprintf(stderr, "Error: Memory allocation failed\n");
    return NULL;
  }

  // 构造 BPF maps 路径
  char full_dir[512];
  snprintf(full_dir, sizeof(full_dir), "%s", pin_dir);

  // 打开所有 BPF maps
  manager->maps.ip_map_fd = open_bpf_map_file(full_dir, "ip_blacklist", NULL);
  manager->maps.cidr_map_fd =
      open_bpf_map_file(full_dir, "ip_cidr_blacklist", NULL);
  manager->maps.port_map_fd =
      open_bpf_map_file(full_dir, "blocked_ports", NULL);
  manager->maps.fw_map_fd = open_bpf_map_file(full_dir, "firewall_rules", NULL);

  // 检查是否成功打开所有 map
  if (manager->maps.ip_map_fd < 0 || manager->maps.cidr_map_fd < 0 ||
      manager->maps.port_map_fd < 0 || manager->maps.fw_map_fd < 0) {
    fprintf(stderr, "❌ Error: Failed to open one or more BPF maps\n");
    destroy_rule_manager(manager);  // 释放已分配资源
    return NULL;
  }

  printf("✅ Rule Manager Initialized Successfully\n");
  return manager;
}

// ✅ 释放 rule_manager_t 资源，关闭所有 map FD
void destroy_rule_manager(rule_manager_t *manager) {
  if (!manager) return;

  if (manager->maps.ip_map_fd > 0) close(manager->maps.ip_map_fd);
  if (manager->maps.cidr_map_fd > 0) close(manager->maps.cidr_map_fd);
  if (manager->maps.port_map_fd > 0) close(manager->maps.port_map_fd);
  if (manager->maps.fw_map_fd > 0) close(manager->maps.fw_map_fd);

  free(manager);
  printf("🗑️ Rule Manager Destroyed\n");
}

// 通用添加规则
int add_rule_helper(rule_manager_t *manager, const rule_t *rule) {
  if (!manager) return -1;

  uint8_t flag = 1;
  int ret = -1;

  switch (rule->type) {
    case RULE_IP:
      ret = bpf_map_update_elem(manager->maps.ip_map_fd, &rule->ip, &flag,
                                BPF_ANY);
      break;
    case RULE_CIDR: {
      ret = bpf_map_update_elem(manager->maps.cidr_map_fd, &rule->cidr, &flag,
                                BPF_ANY);
      break;
    }
    case RULE_PORT: {
      uint16_t key = htons(rule->port);
      ret =
          bpf_map_update_elem(manager->maps.port_map_fd, &key, &flag, BPF_ANY);
      break;
    }
    case RULE_5TUPLE:
      ret = bpf_map_update_elem(manager->maps.fw_map_fd, &rule->tuple, &flag,
                                BPF_ANY);
      break;
    default:
      fprintf(stderr, "❌ Unknown rule type: %d\n", rule->type);
      return -1;
  }

  return ret;
}

// 删除规则
int delete_rule_helper(rule_manager_t *manager, const rule_t *rule) {
  if (!manager) return -1;

  int ret = -1;

  switch (rule->type) {
    case RULE_IP:
      ret = bpf_map_delete_elem(manager->maps.ip_map_fd, &rule->ip);
      break;
    case RULE_CIDR: {
      ret = bpf_map_delete_elem(manager->maps.cidr_map_fd, &rule->cidr);
      break;
    }
    case RULE_PORT: {
      uint16_t key = htons(rule->port);
      ret = bpf_map_delete_elem(manager->maps.port_map_fd, &key);
      break;
    }
    case RULE_5TUPLE:
      ret = bpf_map_delete_elem(manager->maps.fw_map_fd, &rule->tuple);
      break;
    default:
      fprintf(stderr, "❌ Unknown rule type: %d\n", rule->type);
      return -1;
  }

  return ret;
}

// 批量添加规则
int add_rule_batch_helper(rule_manager_t *manager, const rule_t *rules,
                          size_t count) {
  if (!manager || !rules || count == 0) {
    fprintf(stderr, "[C ERROR] Invalid batch input\n");
    return -1;
  }

  int success = 0;
  for (size_t i = 0; i < count; i++) {
    if (add_rule_helper(manager, &rules[i]) < 0) {
      fprintf(stderr, "❌ Failed to add rule[%zu]\n", i);
      continue;
    }
    ++success;
  }
  return success == count ? 0 : -1;
}

// 批量删除规则
int delete_rule_batch_helper(rule_manager_t *manager, const rule_t *rules,
                             size_t count) {
  if (!manager) return -1;

  int success = 0;
  for (size_t i = 0; i < count; ++i) {
    if (delete_rule_helper(manager, &rules[i]) < 0) {
      fprintf(stderr, "❌ Failed to delete rule[%zu]\n", i);
      continue;
    }
    ++success;
  }

  return success == count ? 0 : -1;
}

// IP 黑名单列表
static void list_ip_blacklist(int map_fd) {
  __u32 key = 0, next_key;
  char ip_str[INET_ADDRSTRLEN];

  printf("📌 [IP 黑名单]:\n");
  while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
    key = next_key;
    inet_ntop(AF_INET, &key, ip_str, sizeof(ip_str));
    printf(" - %s\n", ip_str);
  }
}

// CIDR 黑名单列表
static void list_cidr_blacklist(int map_fd) {
  struct lpm_key key = {0}, next_key;
  char ip_str[INET_ADDRSTRLEN];

  printf("📌 [CIDR 黑名单]:\n");
  while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
    key = next_key;
    inet_ntop(AF_INET, &key.ip, ip_str, sizeof(ip_str));
    printf(" - %s/%u\n", ip_str, key.prefixlen);
  }
}

// 端口黑名单列表
static void list_blocked_ports(int map_fd) {
  __u16 key = 0, next_key;

  printf("📌 [端口黑名单]:\n");
  while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
    key = next_key;
    printf(" - %u\n", ntohs(key));
  }
}

// 五元组规则列表
static void list_five_tuple_rules(int map_fd) {
  struct five_tuple key = {0}, next_key;
  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

  printf("📌 [五元组规则]:\n");
  int ret = bpf_map_get_next_key(map_fd, NULL, &key);  // 获取第一个 key
  while (ret == 0) {
    inet_ntop(AF_INET, &key.src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &key.dst_ip, dst_ip, sizeof(dst_ip));

    printf(" - %s:%u -> %s:%u proto=%u\n", src_ip, ntohs(key.src_port), dst_ip,
           ntohs(key.dst_port), key.proto);

    // 获取下一个 key
    ret = bpf_map_get_next_key(map_fd, &key, &next_key);
    if (ret == 0 && memcmp(&key, &next_key, sizeof(key)) == 0) {
      // 防止无限循环：如果 key 和 next_key 相同，则终止
      break;
    }
    key = next_key;
  }
}

// 规则列表查询
int list_rules_helper(rule_manager_t *manager, rule_type_t rule_type) {
  if (!manager) {
    fprintf(stderr, "Error: list_rules received NULL manager\n");
    return -1;
  }

  switch (rule_type) {
    case RULE_IP:
      list_ip_blacklist(manager->maps.ip_map_fd);
      break;
    case RULE_CIDR:
      list_cidr_blacklist(manager->maps.cidr_map_fd);
      break;
    case RULE_PORT:
      list_blocked_ports(manager->maps.port_map_fd);
      break;
    case RULE_5TUPLE:
      list_five_tuple_rules(manager->maps.fw_map_fd);
      break;
    default:  // 未指定时 dump 全部
      list_ip_blacklist(manager->maps.ip_map_fd);
      list_cidr_blacklist(manager->maps.cidr_map_fd);
      list_blocked_ports(manager->maps.port_map_fd);
      list_five_tuple_rules(manager->maps.fw_map_fd);
      break;
  }
  return 0;
}
