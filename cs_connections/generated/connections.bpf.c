#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#include "common.h"
#include "automaton.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("usdt//usr/sbin/nginx:ngx_http_request:http_init_connection")
int BPF_USDT(handle_httpconn, int cnum)
{
    proposition prop = httpconn;


    state new_state = update_state(&cnum, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &cnum);
    submit_rb_event(&new_state, &prop, &vd, &cnum);

    return 0;
}

SEC("usdt//usr/sbin/nginx:ngx_http_request:http_close_connection")
int BPF_USDT(handle_httpclose, int cnum)
{
    proposition prop = httpclose;


    state new_state = update_state(&cnum, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &cnum);
    submit_rb_event(&new_state, &prop, &vd, &cnum);

    return 0;
}

SEC("usdt//usr/sbin/nginx:ngx_http_upstream:verifyauth")
int BPF_USDT(handle_verifyauth, int cnum)
{
    proposition prop = verifyauth;


    state new_state = update_state(&cnum, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &cnum);
    submit_rb_event(&new_state, &prop, &vd, &cnum);

    return 0;
}

SEC("usdt//usr/sbin/nginx:ngx_http_upstream:authelia")
int BPF_USDT(handle_upstreamauthelia, int cnum)
{
    proposition prop = upstreamauthelia;


    state new_state = update_state(&cnum, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &cnum);
    submit_rb_event(&new_state, &prop, &vd, &cnum);

    return 0;
}

SEC("usdt//usr/sbin/nginx:ngx_http_upstream:hello")
int BPF_USDT(handle_upstreamhello, int cnum)
{
    proposition prop = upstreamhello;


    state new_state = update_state(&cnum, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &cnum);
    submit_rb_event(&new_state, &prop, &vd, &cnum);

    return 0;
}

SEC("usdt//usr/sbin/nginx:ngx_http_upstream:auth_res")
int BPF_USDT(handle_authed, int cnum, int status)
{
    if (!(status == 200)) return 0;
proposition prop = authed;


    state new_state = update_state(&cnum, &prop);
    verdict vd = get_verdict(&new_state);
    handle_verdict(&vd, &cnum);
    submit_rb_event(&new_state, &prop, &vd, &cnum);

    return 0;
}