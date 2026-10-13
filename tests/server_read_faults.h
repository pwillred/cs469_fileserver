#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#ifndef SERVER_READ_FAULTS_H
#define SERVER_READ_FAULTS_H
#include <stddef.h>
#include <sys/types.h>
void read_test_cleanse(void *, size_t);
ssize_t read_test_read(int, void *, size_t);
#endif
