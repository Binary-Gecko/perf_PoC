#ifndef __PERF_H__
#define __PERF_H__
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#define MAX_ENUM_TYPE 20
#define MAX_ENUM_CONFIG 20
#define TEST_AUX_OFFSET 0x2000

int perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu, int group_fd, unsigned long flags);
int get_aux_mappable_fd();
#endif