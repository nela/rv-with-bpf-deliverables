#ifndef __AUTOMATON_H
#define __AUTOMATON_H

#include "common.h"

typedef struct automaton_s {

    state rejecting_states[1];
    state initial_state;
    u8 tf_inited;
} automaton_t;

typedef struct aut_tfkey_s {
    state state;
    proposition prop;
} aut_tfkey;

static automaton_t aut = {

    .rejecting_states = { q0 },
    .initial_state = q2,
    .tf_inited = 0
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (state_max * prop_max * 2));
    __type(key, aut_tfkey);
    __type(value, state);
} tf SEC(".maps");

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

static inline void init_aut_transition_function(u8* tf_inited)
{
    if (*tf_inited != 0) return;
    aut_tfkey tfkey;
    state res;

    tfkey.state = q0;
    tfkey.prop = empty;
    res = q0;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.prop = push;
    res = q0;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.prop = pop;
    res = q0;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.state = q2;
    tfkey.prop = pop;
    res = q2;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.prop = empty;
    res = q2;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.prop = push;
    res = q1;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.state = q1;
    tfkey.prop = empty;
    res = q0;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.prop = pop;
    res = q2;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);
    
    tfkey.prop = push;
    res = q1;
    bpf_map_update_elem(&tf, &tfkey, &res, BPF_ANY);    *tf_inited = 1;
    return;
}

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
    // Initialize automaton tf map
init_aut_transition_function(&aut.tf_inited);
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

    aut_tfkey tfkey = { .state = *curr_state, .prop = *prop };
    state* next_state = bpf_map_lookup_elem(&tf, &tfkey);
    if (!next_state) {
        bpf_printk("Invalid next_state pointer\n");
        return -4;
    }
    bpf_map_update_elem(&state_map, entry_id, next_state, BPF_EXIST);
    return *next_state;
}

#endif /* __AUTOMATON_H */
