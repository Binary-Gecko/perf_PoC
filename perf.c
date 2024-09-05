#include "perf.h"
#include <stdio.h>
#include <string.h>

//wrapper since glibc doesn't provide it themselves
int perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

//helper function that searches for an aux mappable PMU
int get_aux_mappable_fd()
{
    for(int t = 0; t<MAX_ENUM_TYPE; t++)
    {
        for(int c=0; c<MAX_ENUM_CONFIG; c++)
        {
            struct perf_event_attr attrs = {0};
            memset((char*)&attrs,0,sizeof(attrs));
            attrs.type = t;
            attrs.size = sizeof(attrs);
            attrs.config = c;
            attrs.disabled = 1;
            attrs.exclude_kernel = 1;
            attrs.exclude_hv = 1;
            int perf_fd = perf_event_open(&attrs,0,-1,-1,0);
            if(perf_fd<0)
            {
                continue;
            }
            void* mapped = mmap(0, 0x1000, PROT_READ|PROT_WRITE,MAP_SHARED, perf_fd, 0);
            if(mapped==MAP_FAILED)
            {
                close(perf_fd);
                continue;
            }
            struct perf_event_mmap_page *user_page = mapped;
            user_page->aux_offset = TEST_AUX_OFFSET;
            user_page->aux_size = 0x1000;
            void* aux_mapped = mmap(0, 0x1000, PROT_READ, MAP_SHARED, perf_fd, TEST_AUX_OFFSET);
            if(aux_mapped != MAP_FAILED)
            {
                printf("[+] Found aux mappable pmu: t=%d, c=%d\n", t, c);
                //Close additional mappings and original event fd
                //and return new fd of same type and config
                munmap(mapped, 0x1000);
                munmap(aux_mapped, 0x1000);
                close(perf_fd);
                return perf_event_open(&attrs,0,-1,-1,0);;
            }
            munmap(mapped, 0x1000);
            close(perf_fd);
        }
    }
    return -1;
}