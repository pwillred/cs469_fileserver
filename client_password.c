/*
 * CS 469
 * Hidden terminal input with bounded storage and scoped signal cleanup.
 */
#define _POSIX_C_SOURCE 200809L
#include "client_password.h"
#include <openssl/crypto.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

static const int watched_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE};

/* Return a pending watched signal, zero for none, or -1 on failure. */
static int pending_signal(void) {
    sigset_t pending;
    if (sigpending(&pending) < 0) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(watched_signals)/sizeof(watched_signals[0]); ++i) {
        if (sigismember(&pending, watched_signals[i]) == 1) {
            return watched_signals[i];
        }
    }
    return 0;
}

int client_read_password(const char *prompt, char *buffer, size_t buffer_size) {
    if (buffer != NULL) {
        OPENSSL_cleanse(buffer, buffer_size);
    }
    if (prompt == NULL || prompt[0] == '\0' || buffer == NULL || buffer_size < 2) {
        return CLIENT_PASSWORD_INVALID_ARGUMENT;
    }
    if (isatty(STDIN_FILENO) != 1) {
        return CLIENT_PASSWORD_NOT_TERMINAL;
    }
    struct termios original;
    if (tcgetattr(STDIN_FILENO, &original) < 0) {
        return CLIENT_PASSWORD_INPUT_ERROR;
    }
    sigset_t watched, previous;
    if (sigemptyset(&watched) < 0) {
        return CLIENT_PASSWORD_INPUT_ERROR;
    }
    for (size_t i = 0; i < sizeof(watched_signals)/sizeof(watched_signals[0]); ++i) {
        if (sigaddset(&watched, watched_signals[i]) < 0) {
            return CLIENT_PASSWORD_INPUT_ERROR;
        }
    }
    if (sigprocmask(SIG_BLOCK, &watched, &previous) < 0) {
        return CLIENT_PASSWORD_INPUT_ERROR;
    }
    struct termios hidden = original;
    hidden.c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON | IEXTEN);
    hidden.c_cc[VMIN] = 1;
    hidden.c_cc[VTIME] = 0;
    int result = CLIENT_PASSWORD_INPUT_ERROR;
    unsigned char byte = 0;
    size_t length = 0;
    size_t limit = buffer_size - 1 < CLIENT_PASSWORD_MAX ? buffer_size - 1 : CLIENT_PASSWORD_MAX;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) < 0 ||
        fputs(prompt, stderr) == EOF || fflush(stderr) == EOF) {
        goto cleanup;
    }
    for (;;) {
        int pending = pending_signal();
        if (pending != 0) {
            result = pending > 0 ? CLIENT_PASSWORD_INTERRUPTED : CLIENT_PASSWORD_INPUT_ERROR;
            break;
        }
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(STDIN_FILENO, &ready);
        struct timeval timeout = {0, 100000};
        int rc = select(STDIN_FILENO + 1, &ready, NULL, NULL, &timeout);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc == 0) continue;
        ssize_t n = read(STDIN_FILENO, &byte, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n != 1 || byte == 4 || byte == 0) break;
        if (byte == '\n' || byte == '\r') {
            buffer[length] = '\0';
            result = length == 0 ? CLIENT_PASSWORD_EMPTY : CLIENT_PASSWORD_OK;
            break;
        }
        if (byte == 127 || byte == '\b') {
            if (length != 0) buffer[--length] = '\0';
            continue;
        }
        if (byte == 21) {
            OPENSSL_cleanse(buffer, length);
            length = 0;
            continue;
        }
        if (length == limit) {
            result = CLIENT_PASSWORD_TOO_LONG;
            break;
        }
        buffer[length++] = (char)byte;
    }
cleanup:
    OPENSSL_cleanse(&byte, sizeof(byte));
    int restore;
    do {
        restore = tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    } while (restore < 0 && errno == EINTR);
    if (restore < 0) result = CLIENT_PASSWORD_INPUT_ERROR;
    if (fputc('\n', stderr) == EOF || fflush(stderr) == EOF) {
        result = CLIENT_PASSWORD_INPUT_ERROR;
    }
    /* Consume only already-pending watched signals while blocked. Input
     * cancellation is reported to the caller after clearing its output buffer.
     */
    int pending;
    while ((pending = pending_signal()) > 0) {
        sigset_t one;
        int received;
        if (sigemptyset(&one) < 0 || sigaddset(&one, pending) < 0 ||
            sigwait(&one, &received) != 0) {
            result = CLIENT_PASSWORD_INPUT_ERROR;
            break;
        }
        result = CLIENT_PASSWORD_INTERRUPTED;
    }
    if (pending < 0) result = CLIENT_PASSWORD_INPUT_ERROR;
    if (result != CLIENT_PASSWORD_OK) OPENSSL_cleanse(buffer, buffer_size);
    if (sigprocmask(SIG_SETMASK, &previous, NULL) < 0) {
        OPENSSL_cleanse(buffer, buffer_size);
        result = CLIENT_PASSWORD_INPUT_ERROR;
    }
    return result;
}
