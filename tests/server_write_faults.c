/* Linked only into the dedicated fault-injection server, never production. */
#include "server_write_faults.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int mode(const char *name) {
    const char *value = getenv("CS469_WRITE_FAULT");
    return value && strcmp(value, name) == 0;
}
size_t fault_fwrite(const void *ptr, size_t size, size_t count, FILE *stream) {
    if (mode("fwrite_zero")) return 0;
    if (mode("fwrite_short") && count > 3) count = 3;
    return fwrite(ptr, size, count, stream);
}
int fault_ferror(FILE *stream) {
    return mode("fwrite_error") || ferror(stream);
}
int fault_fclose(FILE *stream) {
    int result = fclose(stream);
    if (mode("fclose_error")) { errno = EIO; return EOF; }
    return result;
}
ssize_t fault_write(int fd, const void *buffer, size_t count) {
    static _Thread_local int interrupted;
    if (mode("write_eintr") && !interrupted++) { errno = EINTR; return -1; }
    if (mode("write_error")) { errno = ENOSPC; return -1; }
    if (mode("write_zero")) return 0;
    if (mode("write_short") && count > 3) count = 3;
    return write(fd, buffer, count);
}
