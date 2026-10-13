/*
 * CS 469
 * Verified TLS transport for one future file-service operation per connection.
 */
#ifndef CLIENT_TRANSPORT_H
#define CLIENT_TRANSPORT_H
#include "client_config.h"
#include <stddef.h>

typedef struct client_connection client_connection_t;

typedef enum {
    CLIENT_TRANSPORT_OK = 0,
    CLIENT_TRANSPORT_INVALID_ARGUMENT,
    CLIENT_TRANSPORT_NO_MEMORY,
    CLIENT_TRANSPORT_RESOLVE_ERROR,
    CLIENT_TRANSPORT_CONNECT_ERROR,
    CLIENT_TRANSPORT_TLS_CONTEXT_ERROR,
    CLIENT_TRANSPORT_TLS_CA_ERROR,
    CLIENT_TRANSPORT_TLS_VERIFY_ERROR,
    CLIENT_TRANSPORT_TLS_HANDSHAKE_ERROR,
    CLIENT_TRANSPORT_TIMEOUT,
    CLIENT_TRANSPORT_IO_ERROR,
    CLIENT_TRANSPORT_EOF,
    CLIENT_TRANSPORT_PROTOCOL_ERROR
} client_transport_result_t;

#define CLIENT_TRANSPORT_DEFAULT_TIMEOUT_MS 5000

/*
 * Resolve/connect to this endpoint, then immediately establish verified TLS.
 * DNS hostnames use SNI and hostname verification; IP literals use IP SAN checks
 * without SNI. Only ca_file supplies trust; no client certificate or plaintext
 * fallback. Each result owns its socket/context/SSL state. *out is NULL on any
 * failure; pass an unused output slot. Inputs are borrowed only during open.
 * NULL/empty inputs, unterminated endpoint.host, port 0 and NULL out are invalid.
 *
 * Default deadline: 5000 ms total for TCP address attempts + TLS handshake,
 * after synchronous getaddrinfo (DNS resolution itself is not time bounded).
 * timeout_ms must be positive; it also sets each subsequent I/O call's deadline.
 */
int client_connection_open(const client_endpoint_t *endpoint, const char *ca_file,
                           client_connection_t **out);
int client_connection_open_timeout(const client_endpoint_t *endpoint,
                                   const char *ca_file, int timeout_ms,
                                   client_connection_t **out);

/*
 * Transfer exactly length bytes. Zero length succeeds with a healthy connection,
 * even for NULL buffer. NULL connection, or NULL buffer for nonzero length, is
 * invalid. Read calls enter SSL_read immediately, consuming buffered TLS bytes
 * without a socket-readiness wait. WANT_READ/WRITE use the same bounded deadline;
 * partial progress never resets it. On failure some bytes may have transferred:
 * callers must discard the connection, not replay an application operation here.
 * EOF means TLS close_notify before all bytes arrived; abrupt loss is IO_ERROR.
 * Non-EOF TLS record errors are PROTOCOL_ERROR. No payloads are logged.
 */
int client_connection_write_all(client_connection_t *connection,
                                const void *buffer, size_t length);
int client_connection_read_exact(client_connection_t *connection,
                                 void *buffer, size_t length);

/* NULL-safe; single nonblocking close_notify attempt, never waits for peer.
 * No concurrent use or close of a handle is permitted. Distinct handles may be
 * used by different threads. SIGPIPE is suppressed for these operations using
 * a scoped thread signal mask; process-wide signal disposition is unchanged.
 */
void client_connection_close(client_connection_t *connection);

/* Stable, generic diagnostics, never payloads or OpenSSL error-stack contents. */
const char *client_transport_result_string(int result);

/* Classification policy (not a failover algorithm): RESOLVE/CONNECT/TIMEOUT,
 * IO_ERROR and EOF can indicate availability loss. Only the future caller knows
 * whether an application response has begun and whether its command is a read.
 * CA/VERIFY failures are security failures, never failover triggers. CONTEXT,
 * NO_MEMORY, INVALID_ARGUMENT, HANDSHAKE negotiation errors and PROTOCOL errors
 * must not be blindly retried as availability failures. No status bytes or
 * application replies are decoded here, and this module never chooses a replica.
 */
#endif /* CLIENT_TRANSPORT_H */
