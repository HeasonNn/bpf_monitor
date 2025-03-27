#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include <event2/event.h>

#include "ebpf_nat.h"
#include "macros.h"

void signal_cb(evutil_socket_t sig, short events, void *arg);
void stats_timer_cb(evutil_socket_t fd, short events, void *arg);

int run();

#endif  // EVENT_HANDLER_H