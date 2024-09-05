#ifndef __RACE_UTIL_H__
#define __RACE_UTIL_H__
#include <pthread.h>
#define RACE_PARENT 0
#define RACE_CHILD 1
struct race_barrier
{
    pthread_barrier_t barrier;
    volatile int total_waiters;
    volatile int num_waiting;
    volatile int num_ready;
    volatile int num_running;
};

int race_barrier_init(struct race_barrier* barrier, int total_waiters);
int race_barrier_wait_or_abort(struct race_barrier* barrier, volatile int* abort_mem);
#define race_barrier_wait(__barrier) race_barrier_wait_or_abort(__barrier, NULL)

#define SIGNAL_STATE_UNSET 0
#define SIGNAL_STATE_SET 1
#define SIGNAL_STATE_CONSUMED 2
typedef volatile int race_signal_t;

int race_signal_set(race_signal_t* signal);
int race_signal_set_and_wait(race_signal_t* signal);
int race_signal_isset(race_signal_t* signal);
int race_signal_consume(race_signal_t* signal);
#endif