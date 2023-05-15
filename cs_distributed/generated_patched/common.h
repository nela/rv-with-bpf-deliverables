#ifndef __COMMON_H
#define __COMMON_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif /* TASK_COMM_LEN */

typedef enum e_state {
    q4 = 0,
    q3,
    q0,
    q1,
    q2,
    state_max
} state;
typedef enum e_proposition {
    tcpaccepthello = 0,
    req,
    tcpconnectauthelia,
    authed,
    prop_max
} proposition;

typedef enum e_verdict { inconclusive = 0, reject, accept, verdict_max } verdict;

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    proposition prop;
    state state;
    verdict verdict;
    int id;
};

#endif /* __COMMON_H */