/*
 * CS 469
 * Local/offline password database administration. Every command initializes the
 * schema idempotently. Passwords come only from a terminal, never from argv.
 */
#define _POSIX_C_SOURCE 200809L
#include "password_db.h"

#include <openssl/crypto.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

/* Matches the documented password_db.h limit; no private DB header needed. */
#define ADMIN_PASSWORD_MAX 4096

static void usage(void) {
    fputs("Usage:\n"
          "  admin <database> init\n"
          "  admin <database> add <username>\n"
          "  admin <database> passwd <username>\n"
          "  admin <database> delete <username>\n"
          "  admin <database> list\n", stderr);
}

static const char *result_message(int result) {
    switch (result) {
        case PASSWORD_DB_INVALID_ARGUMENT: return "Invalid username or password";
        case PASSWORD_DB_USER_EXISTS: return "User already exists";
        case PASSWORD_DB_USER_NOT_FOUND: return "User not found";
        case PASSWORD_DB_NO_MEMORY: return "Insufficient memory";
        case PASSWORD_DB_CRYPTO_ERROR: return "Password cryptography failed";
        case PASSWORD_DB_STOPPED: return "Unable to write user list";
        case PASSWORD_DB_INVALID_RECORD: return "Invalid password database record";
        default: return "Password database operation failed";
    }
}

/* Common terminal/termination signals are blocked only during hidden input.
 * Polling pending signals lets us restore the terminal before delivering them,
 * without a signal handler or global mutable state. Uncatchable signals such
 * as SIGKILL cannot be handled by any cleanup mechanism.
 */
static int interrupted(const sigset_t *watched) {
    sigset_t pending;
    if (sigpending(&pending) < 0) {
        return 1;
    }
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP};
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        if (sigismember(watched, signals[i]) == 1 &&
            sigismember(&pending, signals[i]) == 1) {
            return 1;
        }
    }
    return 0;
}

/* Noncanonical bounded reads avoid platform canonical-line limits below 4096.
 * Backspace and Ctrl-U edit locally; Ctrl-D cancels. No input bytes are echoed.
 */
static int read_hidden(const char *prompt, char *buffer, const sigset_t *watched) {
    size_t length = 0;
    unsigned char c = 0;
    int success = 0;
    if (fputs(prompt, stderr) == EOF || fflush(stderr) == EOF) {
        goto cleanup;
    }
    for (;;) {
        if (interrupted(watched)) {
            fputs("\nPassword entry interrupted\n", stderr);
            goto cleanup;
        }
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(STDIN_FILENO, &ready);
        struct timeval timeout = {0, 100000};
        int rc = select(STDIN_FILENO + 1, &ready, NULL, NULL, &timeout);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            fputs("\nUnable to read password\n", stderr);
            goto cleanup;
        }
        if (rc == 0) {
            continue;
        }
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n != 1 || c == 4) {
            fputs("\nPassword input ended unexpectedly\n", stderr);
            goto cleanup;
        }
        if (c == '\n' || c == '\r') {
            buffer[length] = '\0';
            success = fputc('\n', stderr) != EOF && fflush(stderr) != EOF;
            goto cleanup;
        }
        if (c == 127 || c == '\b') {
            if (length != 0) {
                buffer[--length] = '\0';
            }
            continue;
        }
        if (c == 21) {
            OPENSSL_cleanse(buffer, length);
            length = 0;
            continue;
        }
        if (c == 0 || length == ADMIN_PASSWORD_MAX) {
            fputs("\nPassword must contain 1-4096 bytes without NUL characters\n", stderr);
            goto cleanup;
        }
        buffer[length++] = (char)c;
    }
cleanup:
    OPENSSL_cleanse(&c, sizeof(c));
    return success;
}

static int password_pair(char *password) {
    char confirmation[ADMIN_PASSWORD_MAX + 1] = {0};
    struct termios original;
    sigset_t watched, previous;
    int masked = 0;
    int changed = 0;
    int success = 0;
    if (tcgetattr(STDIN_FILENO, &original) < 0) {
        fputs("Password entry requires an interactive terminal\n", stderr);
        goto cleanup;
    }
    if (sigemptyset(&watched) < 0 || sigaddset(&watched, SIGINT) < 0 ||
        sigaddset(&watched, SIGTERM) < 0 || sigaddset(&watched, SIGHUP) < 0 ||
        sigaddset(&watched, SIGQUIT) < 0 || sigaddset(&watched, SIGTSTP) < 0 ||
        sigprocmask(SIG_BLOCK, &watched, &previous) < 0) {
        fputs("Unable to protect terminal input\n", stderr);
        goto cleanup;
    }
    masked = 1;
    struct termios hidden = original;
    hidden.c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON | IEXTEN);
    hidden.c_cc[VMIN] = 1;
    hidden.c_cc[VTIME] = 0;
    /* Mark for restoration even if setting the attributes reports failure. */
    changed = 1;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) < 0) {
        fputs("Unable to disable terminal echo\n", stderr);
        goto cleanup;
    }
    if (!read_hidden("Password: ", password, &watched) ||
        !read_hidden("Confirm password: ", confirmation, &watched)) {
        goto cleanup;
    }
    if (password[0] == '\0' || confirmation[0] == '\0') {
        fputs("Password must not be empty\n", stderr);
        goto cleanup;
    }
    if (CRYPTO_memcmp(password, confirmation, ADMIN_PASSWORD_MAX + 1) != 0) {
        fputs("Passwords do not match\n", stderr);
        goto cleanup;
    }
    success = 1;

cleanup:
    if (changed) {
        int rc;
        do {
            rc = tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0) {
            fputs("Unable to restore terminal settings\n", stderr);
            success = 0;
        }
    }
    if (masked && interrupted(&watched)) {
        success = 0;
    }
    OPENSSL_cleanse(confirmation, sizeof(confirmation));
    if (!success) {
        OPENSSL_cleanse(password, ADMIN_PASSWORD_MAX + 1);
    }
    if (masked && sigprocmask(SIG_SETMASK, &previous, NULL) < 0) {
        fputs("Unable to restore signal mask\n", stderr);
        OPENSSL_cleanse(password, ADMIN_PASSWORD_MAX + 1);
        success = 0;
    }
    return success;
}

static int print_user(const char *username, void *context) {
    (void)context;
    return puts(username) == EOF ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage();
        return EXIT_FAILURE;
    }
    const char *command = argv[2];
    int password_command = strcmp(command, "add") == 0 || strcmp(command, "passwd") == 0;
    int needs_user = password_command || strcmp(command, "delete") == 0;
    if ((!needs_user && strcmp(command, "init") != 0 && strcmp(command, "list") != 0) ||
        argc != (needs_user ? 4 : 3)) {
        usage();
        return EXIT_FAILURE;
    }

    /* Broken output pipes must reach checked I/O cleanup, including restoration
     * of terminal attributes if a password prompt cannot be written.
     */
    struct sigaction ignore_pipe = {0};
    ignore_pipe.sa_handler = SIG_IGN;
    if (sigemptyset(&ignore_pipe.sa_mask) < 0 ||
        sigaction(SIGPIPE, &ignore_pipe, NULL) < 0) {
        fputs("Unable to configure output handling\n", stderr);
        return EXIT_FAILURE;
    }

    password_db_t *db = NULL;
    char password[ADMIN_PASSWORD_MAX + 1] = {0};
    int status = EXIT_FAILURE;
    int rc = password_db_open(argv[1], &db);
    if (rc != PASSWORD_DB_OK) {
        fputs("Unable to open password database\n", stderr);
        goto cleanup;
    }
    rc = password_db_init_schema(db);
    if (rc != PASSWORD_DB_OK) {
        fputs("Unable to initialize password database\n", stderr);
        goto cleanup;
    }
    const char *message = NULL;
    if (password_command) {
        if (!password_pair(password)) {
            goto cleanup;
        }
        if (strcmp(command, "add") == 0) {
            rc = password_db_add_user(db, argv[3], password);
            message = "User added";
        } else {
            rc = password_db_change_password(db, argv[3], password);
            message = "Password changed";
        }
        OPENSSL_cleanse(password, sizeof(password));
    } else if (strcmp(command, "delete") == 0) {
        rc = password_db_delete_user(db, argv[3]);
        message = "User deleted";
    } else if (strcmp(command, "list") == 0) {
        rc = password_db_list_users(db, print_user, NULL);
    } else {
        message = "Password database initialized";
    }
    if (rc != PASSWORD_DB_OK) {
        fprintf(stderr, "%s\n", result_message(rc));
        goto cleanup;
    }
    if ((message != NULL && puts(message) == EOF) || fflush(stdout) == EOF) {
        fputs("Unable to write command output\n", stderr);
        goto cleanup;
    }
    status = EXIT_SUCCESS;
cleanup:
    OPENSSL_cleanse(password, sizeof(password));
    password_db_close(db);
    return status;
}
