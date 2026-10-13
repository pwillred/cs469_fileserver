/*
 * CS 469
 * Nonblocking TCP/TLS transport with certificate identity checks and deadlines.
 */
#define _POSIX_C_SOURCE 200809L
#include "client_transport.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct client_connection {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;
    int timeout_ms;
    int failed;
};

/* Prevent OpenSSL's socket writes from terminating the process. Consume only
 * a newly pending SIGPIPE, preserving one that predated this operation.
 */
struct pipe_guard { sigset_t previous; int already_pending; };
static int guard_begin(struct pipe_guard *guard) {
    sigset_t set, pending;
    if (sigemptyset(&set) != 0 || sigaddset(&set, SIGPIPE) != 0 ||
        pthread_sigmask(SIG_BLOCK, &set, &guard->previous) != 0) return 0;
    if (sigpending(&pending) != 0) {
        (void)pthread_sigmask(SIG_SETMASK, &guard->previous, NULL);
        return 0;
    }
    guard->already_pending = sigismember(&pending, SIGPIPE) == 1;
    return 1;
}
static void guard_end(const struct pipe_guard *guard) {
    sigset_t pending, set;
    if (!guard->already_pending && sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
        int received;
        if (sigemptyset(&set) == 0 && sigaddset(&set, SIGPIPE) == 0)
            (void)sigwait(&set, &received);
    }
    (void)pthread_sigmask(SIG_SETMASK, &guard->previous, NULL);
}

static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int wait_socket(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t now = milliseconds();
        if (now < 0) return CLIENT_TRANSPORT_IO_ERROR;
        if (now >= deadline) return CLIENT_TRANSPORT_TIMEOUT;
        int64_t remaining = deadline - now;
        struct pollfd pfd = {fd, events, 0};
        int rc = poll(&pfd, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0 || (rc > 0 && (pfd.revents & POLLNVAL))) return CLIENT_TRANSPORT_IO_ERROR;
        if (rc == 0) continue;
        /* HUP/ERR must reach SSL or SO_ERROR for actual classification. */
        return CLIENT_TRANSPORT_OK;
    }
}

static int tls_failure(client_connection_t *c, int error, int handshake) {
    if (SSL_get_verify_result(c->ssl) != X509_V_OK) return CLIENT_TRANSPORT_TLS_VERIFY_ERROR;
    if (error == SSL_ERROR_ZERO_RETURN) return CLIENT_TRANSPORT_EOF;
    if (error == SSL_ERROR_SYSCALL) return CLIENT_TRANSPORT_IO_ERROR;
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    unsigned long last = ERR_peek_last_error();
    if (error == SSL_ERROR_SSL && ERR_GET_LIB(last) == ERR_LIB_SSL &&
        ERR_GET_REASON(last) == SSL_R_UNEXPECTED_EOF_WHILE_READING) return CLIENT_TRANSPORT_IO_ERROR;
#endif
    return handshake ? CLIENT_TRANSPORT_TLS_HANDSHAKE_ERROR : CLIENT_TRANSPORT_PROTOCOL_ERROR;
}

static void release(client_connection_t *c) {
    if (c == NULL) return;
    SSL_free(c->ssl);
    SSL_CTX_free(c->ctx);
    if (c->fd >= 0) close(c->fd);
    free(c);
}

int client_connection_open(const client_endpoint_t *endpoint, const char *ca_file,
                           client_connection_t **out) {
    return client_connection_open_timeout(endpoint, ca_file, CLIENT_TRANSPORT_DEFAULT_TIMEOUT_MS, out);
}

int client_connection_open_timeout(const client_endpoint_t *endpoint, const char *ca_file,
                                   int timeout_ms, client_connection_t **out) {
    if (out == NULL) return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    *out = NULL;
    if (endpoint == NULL || endpoint->host[0] == 0 ||
        memchr(endpoint->host, 0, sizeof(endpoint->host)) == NULL || endpoint->port == 0 ||
        ca_file == NULL || ca_file[0] == 0 || timeout_ms <= 0) return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    client_connection_t *c = calloc(1, sizeof(*c));
    if (c == NULL) return CLIENT_TRANSPORT_NO_MEMORY;
    c->fd = -1;
    c->timeout_ms = timeout_ms;
    int result = CLIENT_TRANSPORT_TLS_CONTEXT_ERROR;
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (c->ctx == NULL) goto fail;
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION) != 1) goto fail;
    if (SSL_CTX_load_verify_locations(c->ctx, ca_file, NULL) != 1) {
        result = CLIENT_TRANSPORT_TLS_CA_ERROR;
        goto fail;
    }
    char service[6];
    int n = snprintf(service, sizeof(service), "%u", (unsigned int)endpoint->port);
    if (n < 0 || (size_t)n >= sizeof(service)) goto fail;
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;
    if (getaddrinfo(endpoint->host, service, &hints, &addresses) != 0) {
        result = CLIENT_TRANSPORT_RESOLVE_ERROR;
        goto fail;
    }
    int64_t now = milliseconds();
    int64_t deadline = now + timeout_ms;
    result = CLIENT_TRANSPORT_CONNECT_ERROR;
    for (struct addrinfo *a = addresses; now >= 0 && a != NULL; a = a->ai_next) {
        if (milliseconds() >= deadline) { result = CLIENT_TRANSPORT_TIMEOUT; break; }
        int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) { close(fd); continue; }
        int rc = connect(fd, a->ai_addr, a->ai_addrlen);
        if (rc < 0 && (errno == EINPROGRESS || errno == EINTR)) {
            result = wait_socket(fd, POLLOUT, deadline);
            if (result == CLIENT_TRANSPORT_OK) {
                int socket_error = 0;
                socklen_t size = sizeof(socket_error);
                rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &size);
                if (rc == 0 && socket_error != 0) rc = -1;
            }
        } else {
            result = rc == 0 ? CLIENT_TRANSPORT_OK : CLIENT_TRANSPORT_CONNECT_ERROR;
        }
        if (rc == 0 && result == CLIENT_TRANSPORT_OK) { c->fd = fd; break; }
        close(fd);
        if (result == CLIENT_TRANSPORT_TIMEOUT) break;
        result = CLIENT_TRANSPORT_CONNECT_ERROR;
    }
    freeaddrinfo(addresses);
    if (now < 0) result = CLIENT_TRANSPORT_IO_ERROR;
    if (c->fd < 0) goto fail;
    result = CLIENT_TRANSPORT_TLS_CONTEXT_ERROR;
    c->ssl = SSL_new(c->ctx);
    if (c->ssl == NULL || SSL_set_fd(c->ssl, c->fd) != 1) goto fail;
    unsigned char address[sizeof(struct in6_addr)];
    int is_ip = inet_pton(AF_INET, endpoint->host, address) == 1 ||
                inet_pton(AF_INET6, endpoint->host, address) == 1;
    X509_VERIFY_PARAM *params = SSL_get0_param(c->ssl);
    if (is_ip) {
        if (X509_VERIFY_PARAM_set1_ip_asc(params, endpoint->host) != 1) goto fail;
    } else {
        SSL_set_hostflags(c->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(c->ssl, endpoint->host) != 1 ||
            SSL_set_tlsext_host_name(c->ssl, endpoint->host) != 1) goto fail;
    }
    struct pipe_guard guard;
    if (!guard_begin(&guard)) { result = CLIENT_TRANSPORT_IO_ERROR; goto fail; }
    for (;;) {
        now = milliseconds();
        if (now < 0) { result = CLIENT_TRANSPORT_IO_ERROR; break; }
        if (now >= deadline) { result = CLIENT_TRANSPORT_TIMEOUT; break; }
        ERR_clear_error();
        errno = 0;
        int rc = SSL_connect(c->ssl);
        if (rc == 1) {
            result = SSL_get_verify_result(c->ssl) == X509_V_OK
                ? CLIENT_TRANSPORT_OK : CLIENT_TRANSPORT_TLS_VERIFY_ERROR;
            break;
        }
        int error = SSL_get_error(c->ssl, rc);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            result = tls_failure(c, error, 1); break;
        }
        result = wait_socket(c->fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
        if (result != CLIENT_TRANSPORT_OK) break;
    }
    guard_end(&guard);
    if (result != CLIENT_TRANSPORT_OK) goto fail;
    *out = c;
    return CLIENT_TRANSPORT_OK;
fail:
    release(c);
    return result;
}

static int transfer(client_connection_t *c, void *read_buffer, const void *write_buffer,
                    size_t length, int writing) {
    if (c == NULL || (length != 0 && (writing ? write_buffer == NULL : read_buffer == NULL)))
        return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    if (c->failed) return CLIENT_TRANSPORT_IO_ERROR;
    if (length == 0) return CLIENT_TRANSPORT_OK;
    int64_t now = milliseconds();
    if (now < 0) return CLIENT_TRANSPORT_IO_ERROR;
    int64_t deadline = now + c->timeout_ms;
    struct pipe_guard guard;
    if (!guard_begin(&guard)) return CLIENT_TRANSPORT_IO_ERROR;
    int result = CLIENT_TRANSPORT_OK;
    size_t total = 0;
    while (total < length) {
        now = milliseconds();
        if (now < 0) { result = CLIENT_TRANSPORT_IO_ERROR; break; }
        if (now >= deadline) { result = CLIENT_TRANSPORT_TIMEOUT; break; }
        int chunk = length - total > 16384 ? 16384 : (int)(length - total);
        ERR_clear_error();
        errno = 0;
        /* Always try SSL first: buffered decrypted bytes need no socket event.
         * Retry unchanged pointers/length after WANT_READ or WANT_WRITE.
         */
        int n = writing ? SSL_write(c->ssl, (const char *)write_buffer + total, chunk)
                        : SSL_read(c->ssl, (char *)read_buffer + total, chunk);
        if (n > 0) { total += (size_t)n; continue; }
        int error = SSL_get_error(c->ssl, n);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            result = tls_failure(c, error, 0); break;
        }
        result = wait_socket(c->fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
        if (result != CLIENT_TRANSPORT_OK) break;
    }
    guard_end(&guard);
    if (result != CLIENT_TRANSPORT_OK) c->failed = 1;
    return result;
}

int client_connection_read_exact(client_connection_t *c, void *buffer, size_t length) {
    return transfer(c, buffer, NULL, length, 0);
}
int client_connection_write_all(client_connection_t *c, const void *buffer, size_t length) {
    return transfer(c, NULL, buffer, length, 1);
}
void client_connection_close(client_connection_t *c) {
    if (c == NULL) return;
    struct pipe_guard guard;
    if (!c->failed && c->ssl != NULL && guard_begin(&guard)) {
        ERR_clear_error();
        (void)SSL_shutdown(c->ssl); /* One nonblocking best-effort attempt. */
        guard_end(&guard);
    }
    release(c);
}
const char *client_transport_result_string(int result) {
    switch (result) {
        case CLIENT_TRANSPORT_OK: return "Success";
        case CLIENT_TRANSPORT_INVALID_ARGUMENT: return "Invalid transport arguments";
        case CLIENT_TRANSPORT_NO_MEMORY: return "Insufficient memory";
        case CLIENT_TRANSPORT_RESOLVE_ERROR: return "Endpoint resolution failed";
        case CLIENT_TRANSPORT_CONNECT_ERROR: return "TCP connection failed";
        case CLIENT_TRANSPORT_TLS_CONTEXT_ERROR: return "TLS setup failed";
        case CLIENT_TRANSPORT_TLS_CA_ERROR: return "Unable to load configured CA";
        case CLIENT_TRANSPORT_TLS_VERIFY_ERROR: return "Server certificate or identity verification failed";
        case CLIENT_TRANSPORT_TLS_HANDSHAKE_ERROR: return "TLS negotiation failed";
        case CLIENT_TRANSPORT_TIMEOUT: return "Transport deadline expired";
        case CLIENT_TRANSPORT_IO_ERROR: return "Connection I/O failed";
        case CLIENT_TRANSPORT_EOF: return "Peer closed TLS before transfer completed";
        default: return "Transport protocol error";
    }
}
