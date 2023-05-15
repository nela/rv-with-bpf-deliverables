#ifndef __AUTOMATON_H
#define __AUTOMATON_H

#include "common.h"

typedef struct automaton_s {

    state rejecting_states[1];
    state initial_state;
    state tf[state_max][prop_max];
} automaton_t;



static automaton_t aut = {

    .rejecting_states = { q0 },
    .initial_state = q2,
    .tf = {
        { q0, q0, q0 },
        { q2, q1, q2 },
        { q0, q1, q2 }
    }
};



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, state);
} state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");



static inline verdict get_verdict(state* state)
{
    int len = 
        sizeof(aut.rejecting_states) /
        sizeof(aut.rejecting_states[0]);
    
    for (int i = 0; i < len; i++) {
        if (aut.rejecting_states[i] == *state)
            return reject;
    }

    

    return inconclusive;
}

static inline void handle_verdict(verdict* vd, int* entry_id)
{
    if (*vd == reject) {
        bpf_printk("Sending KILL signal\n");
        bpf_send_signal(9);
        // bpf_map_delete_elem(&state_map, entry_id);
    } else if (*vd == accept) {
        bpf_printk("Deleting accepted element\n");
        bpf_map_delete_elem(&state_map, entry_id);
    }
}

static inline void submit_rb_event(state* state, proposition* prop,
                                   verdict* verdict, int* entry_id)
{
    struct event* e;
    struct task_struct* task;
    u64 id, ts;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    /* fill out the sample with data */
    e->pid = pid;
    e->state = *state;
    e->prop = *prop;
    e->verdict = *verdict;
    e->id = *entry_id;
    task = (struct task_struct*)bpf_get_current_task();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
}

static inline state update_state(int* entry_id, proposition* prop)
{
    
    state* curr_state = bpf_map_lookup_elem(&state_map, entry_id);

    // Initialize state map
    if (!curr_state) {
        int res = bpf_map_update_elem(&state_map, entry_id,
                                      &aut.initial_state, BPF_NOEXIST);

        if (res < 0) {
            bpf_printk("Unable to initialize map..\n");
            return -1;
        }

        curr_state = bpf_map_lookup_elem(&state_map, entry_id);
        if (!curr_state) {
            bpf_printk("Something went wrong with state initialization..\n");
            return -1;
        }
    }

    if (*curr_state < 0 || *curr_state >= state_max) {
       bpf_printk("Invalid bounds for curr_state\n");
       return -1;
    }
    if (*prop < 0 || *prop >= prop_max) {
       bpf_printk("Invalid bounds for proposition\n");
       return -1;
    }
    state next_state = aut.tf[*curr_state][*prop];
    if (next_state < 0 || next_state >= state_max) {
       bpf_printk("Invalid bounds for next_state\n");
       return -1;
    }
    bpf_map_update_elem(&state_map, entry_id, &next_state, BPF_EXIST);
    return next_state;
}

#endif /* __AUTOMATON_H */
