#pragma once

#include <arpa/inet.h>

#include "prog_helper.h"

#define MAP_IP_BLACKLIST "ip_blacklist"
#define MAP_CIDR_BLACKLIST "ip_cidr_blacklist"
#define MAP_BLOCKED_PORTS "blocked_ports"
#define MAP_FIREWALL_RULES "firewall_rules"

// 规则类型
typedef enum { RULE_IP, RULE_CIDR, RULE_PORT, RULE_5TUPLE } rule_type_t;

// 规则动作
typedef enum { ACTION_DROP, ACTION_ACCEPT } rule_action_t;

// 五元组规则
typedef struct {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
} rule_5tuple_t;

// CIDR 结构
typedef struct {
  uint32_t prefixlen;  // 前缀长度
  uint32_t ip;         // 存储 IPv4 地址
} rule_cidr_t;

// 统一的规则结构
typedef struct {
  rule_type_t type;
  rule_action_t action;
  union {
    uint32_t ip;          // 存储 IPv4 地址
    rule_cidr_t cidr;     // CIDR
    uint16_t port;        // 端口
    rule_5tuple_t tuple;  // 五元组
  };
} rule_t;

// 规则映射 FD 结构
typedef struct {
  int ip_map_fd;
  int cidr_map_fd;
  int port_map_fd;
  int fw_map_fd;
  int bpf_obj_fd;  // 统一管理 BPF 对象
} rule_map_set_t;

// 规则管理器
typedef struct {
  rule_map_set_t maps;
  int is_initialized;
} rule_manager_t;

// 规则管理器初始化与销毁
rule_manager_t *create_rule_manager(char *pin_dir);
void destroy_rule_manager(rule_manager_t *manager);

// 内部实现函数
int add_rule_helper(rule_manager_t *manager, const rule_t *rule);
int delete_rule_helper(rule_manager_t *manager, const rule_t *rule);
int add_rule_batch_helper(rule_manager_t *manager, const rule_t *rules,
                          size_t count);
int delete_rule_batch_helper(rule_manager_t *manager, const rule_t *rules,
                             size_t count);
int list_rules_helper(rule_manager_t *manager, rule_type_t rule_type);
