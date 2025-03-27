#pragma once

#include "rule_helper.h"

int add_rule(const rule_t *rule);
int delete_rule(const rule_t *rule);
int add_rule_batch(const rule_t *rules, size_t count);
int delete_rule_batch(const rule_t *rules, size_t count);
int list_rules(rule_type_t rule_type);