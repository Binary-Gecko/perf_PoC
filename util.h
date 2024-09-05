#ifndef __UTIL_H__
#define __UTIL_H__
#include <stddef.h>
#include <stdlib.h>
#define perror_exit(s) do{perror(s); exit(-1);}while(0);
void hexdump(char* data, size_t nBytes);
void assignToThisCore(int core_id);
#endif