#define _GNU_SOURCE
#include "race_util.h"
#include <pthread.h>
#include <string.h>
#include <sched.h>
int race_barrier_init(struct race_barrier* barrier, int total_waiters)
{
    memset(barrier, 0, sizeof(*barrier));
    pthread_barrierattr_t attr = {0};
    pthread_barrierattr_init(&attr);
    pthread_barrierattr_setpshared(&attr, 1);
    pthread_barrier_init(&barrier->barrier,&attr,total_waiters);
    return 0;
}

int race_barrier_wait_or_abort(struct race_barrier* barrier, volatile int* abort_mem)
{
    return pthread_barrier_wait(&barrier->barrier);
}

int race_signal_set(race_signal_t* signal)
{
    if(*signal==SIGNAL_STATE_SET)
        return -1;
    *signal = SIGNAL_STATE_SET;
    return 0;
}

int race_signal_set_and_wait(race_signal_t* signal)
{
    if(*signal==SIGNAL_STATE_SET)
        return -1;
    *signal = SIGNAL_STATE_SET;
    //Wait for signal to be consumed
    while(*signal != SIGNAL_STATE_CONSUMED)
        sched_yield();
    *signal = SIGNAL_STATE_UNSET;
    return 0;
}

int race_signal_isset(race_signal_t* signal)
{
    return *signal == SIGNAL_STATE_SET;
}

int race_signal_consume(race_signal_t* signal)
{
    if(*signal!=SIGNAL_STATE_SET)
        return -1;
    *signal = SIGNAL_STATE_CONSUMED;
}