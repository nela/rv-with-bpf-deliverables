#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "connections.skel.h"
#include "common.h"

const char * state_lookup[state_max];
const char * prop_lookup[prop_max];
const char * verdict_lookup[verdict_max];

static void init_lookup() {
    state_lookup[q4] = "q4";
    state_lookup[q7] = "q7";
    state_lookup[q1] = "q1";
    state_lookup[q0] = "q0";
    state_lookup[q6] = "q6";
    state_lookup[q3] = "q3";
    state_lookup[q2] = "q2";
    state_lookup[q5] = "q5";

    prop_lookup[httpconn] = "httpconn";
    prop_lookup[httpclose] = "httpclose";
    prop_lookup[verifyauth] = "verifyauth";
    prop_lookup[upstreamauthelia] = "upstreamauthelia";
    prop_lookup[upstreamhello] = "upstreamhello";
    prop_lookup[authed] = "authed";

    verdict_lookup[inconclusive] = "INCONCLUSIVE";
    verdict_lookup[reject] = "REJECTED";
    verdict_lookup[accept] = "ACCEPTED";

    return;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-10s %-10s %-10d %-20s %-10s %-16s %d\n", ts, e->comm, e->pid,
            prop_lookup[e->prop],
            state_lookup[e->state],
            verdict_lookup[e->verdict],
            e->id);

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
        exiting = true;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct connections_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    init_lookup();

    /* Open load and verify BPF application */
    skel = connections_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Attach tracepoint handler */
    err = connections_bpf__attach(skel);
    if (err) {
            fprintf(stderr, "Failed to attach BPF skeleton\n");
            goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    printf("%-10s %-10s %-10s %-20s %-10s %-16s %s\n",
           "TIME", "COMM", "PID", "PROPOSITION", "STATE", "VERDICT", "ENTRY_ID");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    connections_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}