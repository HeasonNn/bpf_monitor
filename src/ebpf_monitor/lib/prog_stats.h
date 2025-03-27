#pragma once
#include <time.h>

#include "types.h"
#include "prog_helper.h"

#define NANOSEC_PER_SEC 1000000000  // 10^9

int ebpf_prog_stats(struct config *cfg);