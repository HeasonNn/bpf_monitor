#include "rule_api.h"

static rule_manager_t *rule_manager = NULL;

static rule_manager_t *get_rule_manager() {
  if (!rule_manager) {
    char pin_dir[512];
    snprintf(pin_dir, sizeof(pin_dir), "%s/%s", PIN_BASE_DIR, INTERFACE);
    rule_manager = create_rule_manager(pin_dir);
  }
  return rule_manager;
}

int add_rule(const rule_t *rule) {
  if (!rule) return -1;

  rule_manager_t *manager = get_rule_manager();
  if (!manager) return -1;

  return add_rule_helper(manager, rule);
}

int delete_rule(const rule_t *rule) {
  if (!rule) return -1;

  rule_manager_t *manager = get_rule_manager();
  if (!manager) return -1;

  return delete_rule_helper(manager, rule);
}

int add_rule_batch(const rule_t *rules, size_t count) {
  if (!rules || count == 0) return -1;

  rule_manager_t *manager = get_rule_manager();
  if (!manager) return -1;

  return add_rule_batch_helper(manager, rules, count);
}

int delete_rule_batch(const rule_t *rules, size_t count) {
  if (!rules || count == 0) return -1;

  rule_manager_t *manager = get_rule_manager();
  if (!manager) return -1;

  return delete_rule_batch_helper(manager, rules, count);
}

int list_rules(rule_type_t rule_type) {
  rule_manager_t *manager = get_rule_manager();
  if (!manager) return -1;

  return list_rules_helper(manager, rule_type);
}