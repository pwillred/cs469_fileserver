#include "server_protocol_io.h"
#include <openssl/err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>

static int64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void abort_io(void *opaque) {
    server_protocol_io_t *io = opaque;
    io->aborted = 1;
    (void)shutdown(io->fd, SHUT_RDWR);
}
static int transfer(server_protocol_io_t *io, void *data, size_t length, int writing) {
    if (io->aborted) return -1;
    /* SSL_read can also write (TLS control messages). Block SIGPIPE only in the
     * calling thread, preserving a signal that was already pending. */
    sigset_t set, previous, pending;
    sigemptyset(&set); sigaddset(&set, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &set, &previous) != 0) return -1;
    if (sigpending(&pending) != 0) {
        (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
        return -1;
    }
    int was_pending = sigismember(&pending, SIGPIPE) == 1;
    int rc = -1;
    unsigned char *bytes = data;
    while (length) {
        int64_t now = now_ms();
        if (now < 0 || now >= io->deadline) goto done;
        int amount = length > INT_MAX ? INT_MAX : (int)length;
        ERR_clear_error();
        int n = writing ? SSL_write(io->ssl, bytes, amount) : SSL_read(io->ssl, bytes, amount);
        if (n > 0) { bytes += n; length -= (size_t)n; continue; }
        int error = SSL_get_error(io->ssl, n);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) goto done;
        /* Try SSL first so buffered decrypted records never wait on the socket. */
        for (;;) {
            now = now_ms();
            if (now < 0 || now >= io->deadline) goto done;
            int64_t left = io->deadline - now;
            struct pollfd pfd = {io->fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, 0};
            int ready = poll(&pfd, 1, left > INT_MAX ? INT_MAX : (int)left);
            if (ready < 0 && errno == EINTR) continue;
            if (ready <= 0 || (pfd.revents & POLLNVAL)) goto done;
            break;
        }
    }
    rc = 0;
done:
    if (!was_pending && sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
        int signal_number;
        (void)sigwait(&set, &signal_number);
    }
    (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
    return rc;
}
static int read_exact(void *p, void *b, size_t n) { return transfer(p, b, n, 0); }
static int write_all(void *p, const void *b, size_t n) { return transfer(p, (void *)b, n, 1); }
int server_protocol_io_init(server_protocol_io_t *state, SSL *ssl, int timeout_ms, server_read_io_t *out) {
    if (!state || !ssl || !out || timeout_ms <= 0 || !SSL_is_init_finished(ssl)) return -1;
    int fd = SSL_get_fd(ssl);
    int flags = fd < 0 ? -1 : fcntl(fd, F_GETFL);
    int64_t now = now_ms();
    if (flags < 0 || now < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    *state = (server_protocol_io_t){ssl, fd, now + timeout_ms, 0};
    *out = (server_read_io_t){state, read_exact, write_all, abort_io};
    return 0;
}
