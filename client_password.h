/*
 * CS 469
 * Secure interactive password input for the local client.
 */
#ifndef CLIENT_PASSWORD_H
#define CLIENT_PASSWORD_H
#include <stddef.h>

/* Database-compatible local limit, not a promise about the future wire format. */
#define CLIENT_PASSWORD_MAX 4096

typedef enum {
    CLIENT_PASSWORD_OK = 0,
    CLIENT_PASSWORD_INVALID_ARGUMENT,
    CLIENT_PASSWORD_NOT_TERMINAL,
    CLIENT_PASSWORD_INPUT_ERROR,
    CLIENT_PASSWORD_EMPTY,
    CLIENT_PASSWORD_TOO_LONG,
    CLIENT_PASSWORD_INTERRUPTED
} client_password_result_t;

/*
 * Read one password from terminal stdin; prompt goes to stderr. No confirmation.
 * buffer_size includes the terminator; at most min(buffer_size-1,4096) bytes
 * are accepted. Never truncates. Caller owns the buffer and must cleanse it
 * after use. Any failure clears the entire supplied valid buffer.
 * NULL/empty prompt, NULL buffer or size < 2 is invalid. No input is logged.
 * Terminal state and signal mask are restored on all handled paths. SIGINT,
 * SIGTERM, SIGHUP, SIGQUIT (and broken prompt pipes) cancel with INTERRUPTED
 * after cleanup rather than terminating the process. Uncatchable signals and
 * terminal-device loss cannot guarantee restoration.
 * Intended for the single-threaded interactive CLI: signal masks and terminal
 * input must not be concurrently manipulated. No global buffers/handlers.
 * Noncanonical input supports the full limit: backspace edits, Ctrl-U clears,
 * Ctrl-D cancels; newline ends input. Other terminal signal/flow controls retain
 * their terminal meanings. Embedded NUL is rejected.
 */
int client_read_password(const char *prompt, char *buffer, size_t buffer_size);
#endif /* CLIENT_PASSWORD_H */
