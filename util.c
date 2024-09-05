#define _GNU_SOURCE
#include "util.h"
#include <stdio.h>
#include <sched.h>

void hexdump(char* data, size_t nBytes)
{
    char dump_buf[140];
    int idx=0,sidx = 0;
    printf("dump@%p\n",data);
    while(idx<nBytes)
    {
        int lineStart = idx;
        for (int i = 0; i < 64; i++) {
            snprintf(dump_buf+ sidx, 3, "%02X", (unsigned int) (((char *) data)[idx]));
            sidx+=2;
            idx++;
            if(idx==nBytes)
                break;
        }
        printf("dump: +%04x: %s\n", lineStart,dump_buf);
        sidx=0;
    }
}

void assignToThisCore(int core_id)
{
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}