#include "event_handler.h"

void signal_cb(evutil_socket_t sig, short events, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    printf("\nCaught interrupt signal; exiting...\n");
    exiting = 1;
    cleanup_tc_hook();
    event_base_loopexit(base, NULL);
}

void stats_timer_cb(evutil_socket_t fd, short events, void *arg)
{
    stats_context_t *ctx = (stats_context_t *)arg;

    if (exiting)
    {
        printf("Exiting stats polling...\n");
        cleanup_tc_hook();
        return;
    }

    stats_poll_step(ctx);
}

int run()
{
    struct event_base *base = event_base_new();
    if (!base)
    {
        fprintf(stderr, "Failed to create event base\n");
        return EXIT_FAIL;
    }

    struct event *signal_event = evsignal_new(base, SIGINT, signal_cb, base);

    if (!signal_event || event_add(signal_event, NULL) < 0)
    {
        fprintf(stderr, "Could not create/add a signal event!\n");
        return EXIT_FAIL;
    }

    stats_context_t ctx;
    stats_poll_init(&ctx);
    stats_poll_step(&ctx);

    struct timeval stats_interval = {2, 0};

    struct event *stats_event =
        event_new(base, -1, EV_PERSIST, stats_timer_cb, &ctx);

    if (!stats_event || event_add(stats_event, &stats_interval) < 0)
    {
        fprintf(stderr, "Could not create/add a timer event!\n");
        return EXIT_FAIL;
    }

    printf("Starting stats polling. Press Ctrl+C to stop.\n");
    event_base_dispatch(base);

    event_free(stats_event);
    event_free(signal_event);
    event_base_free(base);

    printf("Exited cleanly.\n");
    return EXIT_OK;
}