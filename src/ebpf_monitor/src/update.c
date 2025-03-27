#include "rule_api.h"

void test_add_rule() {
  printf("\n=== Testing add_rule() ===\n");

  // 添加 IP 规则
  rule_t ip_rule = {.type = RULE_IP, .ip = inet_addr("192.168.1.100")};
  int res = add_rule(&ip_rule);
  printf("Add IP Rule: %s\n", res == 0 ? "Success" : "Failed");

  // 添加 CIDR 规则
  rule_t cidr_rule = {
      .type = RULE_CIDR, .cidr.ip = inet_addr("10.0.0.0"), .cidr.prefixlen = 8};
  res = add_rule(&cidr_rule);
  printf("Add CIDR Rule: %s\n", res == 0 ? "Success" : "Failed");

  // 添加端口规则
  rule_t port_rule = {.type = RULE_PORT, .port = htons(80)};
  res = add_rule(&port_rule);
  printf("Add Port Rule: %s\n", res == 0 ? "Success" : "Failed");

  // 添加五元组规则
  rule_t tuple_rule = {
      .type = RULE_5TUPLE,
      .tuple.src_ip = inet_addr("192.168.1.1"),
      .tuple.dst_ip = inet_addr("10.0.0.5"),
      .tuple.src_port = htons(1234),
      .tuple.dst_port = htons(443),
      .tuple.proto = 6  // TCP
  };
  res = add_rule(&tuple_rule);
  printf("Add 5-Tuple Rule: %s\n", res == 0 ? "Success" : "Failed");
}

void test_delete_rule() {
  printf("\n=== Testing delete_rule() ===\n");

  // 删除 IP 规则
  rule_t ip_rule = {.type = RULE_IP, .ip = inet_addr("192.168.1.100")};
  int res = delete_rule(&ip_rule);
  printf("Delete IP Rule: %s\n", res == 0 ? "Success" : "Failed");

  // 删除 CIDR 规则
  rule_t cidr_rule = {
      .type = RULE_CIDR, .cidr.ip = inet_addr("10.0.0.0"), .cidr.prefixlen = 8};
  res = delete_rule(&cidr_rule);
  printf("Delete CIDR Rule: %s\n", res == 0 ? "Success" : "Failed");

  // 删除端口规则
  rule_t port_rule = {.type = RULE_PORT, .port = htons(80)};
  res = delete_rule(&port_rule);
  printf("Delete Port Rule: %s\n", res == 0 ? "Success" : "Failed");

  // 删除五元组规则
  rule_t tuple_rule = {
      .type = RULE_5TUPLE,
      .tuple.src_ip = inet_addr("192.168.1.1"),
      .tuple.dst_ip = inet_addr("10.0.0.5"),
      .tuple.src_port = htons(1234),
      .tuple.dst_port = htons(443),
      .tuple.proto = 6  // TCP
  };
  res = delete_rule(&tuple_rule);
  printf("Delete 5-Tuple Rule: %s\n", res == 0 ? "Success" : "Failed");
}

void test_batch_operations() {
  printf("\n=== Testing batch add/delete rules ===\n");

  rule_t rules[3] = {{.type = RULE_IP, .ip = inet_addr("192.168.2.200")},
                     {.type = RULE_CIDR,
                      .cidr.ip = inet_addr("172.16.0.0"),
                      .cidr.prefixlen = 16},
                     {.type = RULE_PORT, .port = htons(22)}};

  int res = add_rule_batch(rules, 3);
  printf("Batch Add Rules: %s\n", res == 0 ? "Success" : "Failed");

  res = delete_rule_batch(rules, 3);
  printf("Batch Delete Rules: %s\n", res == 0 ? "Success" : "Failed");
}

void test_list_rules() {
  printf("\n=== Testing list_rules() ===\n");

  printf("Listing all rules:\n");
  list_rules(RULE_IP);
  list_rules(RULE_CIDR);
  list_rules(RULE_PORT);
  list_rules(RULE_5TUPLE);
}

int main(int argc, char **argv) {
  printf("\n🚀 Starting API Tests...\n");

  test_add_rule();
  test_list_rules();
  test_delete_rule();
  test_batch_operations();
  test_list_rules();

  printf("\n✅ All tests completed!\n");
  return 0;
}