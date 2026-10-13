#ifndef SERVER_PROTOCOL_FIELDS_H
#define SERVER_PROTOCOL_FIELDS_H
#include "server_read_ops.h"
#include <stdint.h>
/* Returns decoded span including NUL, or zero on I/O failure/no terminator.
 * Validation belongs to auth/filename policy; never reads beyond capacity. */
static inline size_t server_read_field(const server_read_io_t *io, char *out, size_t capacity) {
    for (size_t i = 0; i < capacity; ++i) {
        if (io->read_exact(io->state, out + i, 1) != 0) return 0;
        if (out[i] == 0) return i + 1;
    }
    return 0;
}
static inline uint8_t server_status_byte(error_code_t status) {
    switch (status) {
        case ERR_OK: return 0;
        case ERR_AUTH_FAILED: return 1;
        case ERR_NOT_FOUND: return 2;
        case ERR_EXISTS: return 3;
        case ERR_BAD_REQUEST: return 4;
        case ERR_TOO_LARGE: return 5;
        case ERR_REPLICATION_FAILED: return 6;
        default: return 7;
    }
}
static inline int server_write_status(const server_read_io_t *io, error_code_t status) {
    uint8_t byte = server_status_byte(status);
    return io->write_all(io->state, &byte, sizeof(byte));
}
#endif
