#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>


#include "common.h"
#include "automaton.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


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

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcpconnectauthelia)
{
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