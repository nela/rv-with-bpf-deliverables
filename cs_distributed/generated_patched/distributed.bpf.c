#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>


#include "common.h"
#include "automaton.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef NGX_COMM_LEN
#define NGX_COMM_LEN 6
#endif

static inline __attribute((always_inline)) int _bswap16(u16 val) {
    return ((val & 0x0ff) << 8) | ((val & 0xff00) >> 8);
}

static inline __attribute((always_inline)) int _is_ngx_comm(char *name) {
    char ngx[] = "nginx";
    for (int i = 0; i < 5; ++i) {
    if (ngx[i] != name[i])
      return 0;
    }
    return 1;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, struct sock *);
} currsock SEC(".maps");


SEC("uprobe//usr/sbin/nginx:ngx_http_create_request")
int BPF_KPROBE(handle_req)
{
    proposition prop = req;

    /* WARNING - the solution below provides only one value as a key
   which implies it can only keep state of a single object */
        int entry_id = 0;
    state new_state = update_state(&entry_id, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &entry_id);
    submit_rb_event(&new_state, &prop, &vd, &entry_id);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect_entry, struct sock *sk)
{
    char task[NGX_COMM_LEN];
    bpf_get_current_comm(&task, sizeof(task));

    if (!_is_ngx_comm(task)) return 0;

    u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&currsock, &tid, &sk, 0 /* flags */);

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcpconnectauthelia)
{
    char task[NGX_COMM_LEN];
    bpf_get_current_comm(&task, sizeof(task));
    if (!_is_ngx_comm(task)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&currsock, &pid_tgid);
    if (!skpp) return -1;

    struct sock *skp = *skpp;
    u16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);
    dport = _bswap16(dport);

    if (!(dport == 9091)) return 0;
proposition prop = tcpconnectauthelia;

    /* WARNING - the solution below provides only one value as a key
   which implies it can only keep state of a single object */
        int entry_id = 0;
    state new_state = update_state(&entry_id, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &entry_id);
    submit_rb_event(&new_state, &prop, &vd, &entry_id);

    return 0;
}

SEC("uprobe//usr/bin/node:uv_accept")
int BPF_KPROBE(handle_tcpaccepthello)
{
    proposition prop = tcpaccepthello;

    /* WARNING - the solution below provides only one value as a key
   which implies it can only keep state of a single object */
        int entry_id = 0;
    state new_state = update_state(&entry_id, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &entry_id);
    submit_rb_event(&new_state, &prop, &vd, &entry_id);

    return 0;
}

SEC("usdt//usr/sbin/nginx:ngx_http_upstream:auth_res")
int BPF_USDT(handle_authed, int cnum, int http_status)
{
    if (!(http_status == 200)) return 0;
proposition prop = authed;

    /* WARNING - the solution below provides only one value as a key
   which implies it can only keep state of a single object */
        int entry_id = 0;
    state new_state = update_state(&entry_id, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &entry_id);
    submit_rb_event(&new_state, &prop, &vd, &entry_id);

    return 0;
}
