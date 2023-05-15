#ifndef __COMMON_H
#define __COMMON_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif /* TASK_COMM_LEN */

typedef enum e_state {
    q0 = 0,
    q7,
    q3,
    q6,
    q2,
    q4,
    q5,
    q1,
    state_max
} state;
typedef enum e_proposition {
    httpclose = 0,
    httpconn,
    authed,
    upstreamhello,
    verifyauth,
    upstreamauthelia,
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