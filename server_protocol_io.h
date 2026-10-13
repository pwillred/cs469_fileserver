#ifndef SERVER_PROTOCOL_IO_H
#define SERVER_PROTOCOL_IO_H
#include "server_read_ops.h"
#include <openssl/ssl.h>
#include <stdint.h>
/* Per-connection adapter, initialized AFTER a successful TLS handshake.
 * Sets socket nonblocking and leaves it that way. Borrows SSL/socket: caller
 * closes/frees them after one operation; no concurrent use of the same SSL.
 * One monotonic deadline covers the entire request/response (not DB/disk work).
 * Use the server's configured timeout, e.g. 15000ms. No global signal changes. */
typedef struct { SSL *ssl; int fd; int64_t deadline; int aborted; } server_protocol_io_t;
int server_protocol_io_init(server_protocol_io_t *, SSL *, int timeout_ms, server_read_io_t *);
#endif
