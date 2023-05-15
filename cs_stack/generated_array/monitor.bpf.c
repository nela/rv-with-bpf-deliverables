#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"
#include "automaton.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("uretprobe//usr/local/bin/stack:empty")
int BPF_KRETPROBE(handle_empty, int retval)
{
    if (!(retval == 1)) return 0;
proposition prop = empty;

    /* WARNING - the solution below provides only one value as a key
   which implies it can only keep state of a single object */
        int entry_id = 0;
    state new_state = update_state(&entry_id, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &entry_id);
    submit_rb_event(&new_state, &prop, &vd, &entry_id);

    return 0;
}

SEC("uprobe//usr/local/bin/stack:push")
int BPF_KPROBE(handle_push)
{
    proposition prop = push;

    /* WARNING - the solution below provides only one value as a key
   which implies it can only keep state of a single object */
        int entry_id = 0;
    state new_state = update_state(&entry_id, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &entry_id);
    submit_rb_event(&new_state, &prop, &vd, &entry_id);

    return 0;
}

SEC("uprobe//usr/local/bin/stack:pop")
int BPF_KPROBE(handle_pop)
{
    proposition prop = pop;

    /* WARNING - the solution below provides only one value as a key
   which implies it can only keep state of a single object */
        int entry_id = 0;
    state new_state = update_state(&entry_id, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &entry_id);
    submit_rb_event(&new_state, &prop, &vd, &entry_id);

    return 0;
}