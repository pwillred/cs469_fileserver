/* Test-only declarations, force-included into the command object, never production. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <sys/types.h>
#include <stddef.h>
ssize_t client_test_read(int fd, void *buffer, size_t size);
ssize_t client_test_write(int fd, const void *buffer, size_t size);
