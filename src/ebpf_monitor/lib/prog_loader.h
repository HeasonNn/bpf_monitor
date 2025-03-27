#pragma once

#include <xdp/libxdp.h>

#include "prog_helper.h"
#include "types.h"

int ebpf_prog_loader(struct config *cfg);