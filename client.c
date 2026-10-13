/*
 * CS 469
 * Client CLI foundation. Validates local configuration only; does not execute
 * file operations. Secure password input is local only; networking remains future work.
 */
#include "client_config.h"
#include "client_password.h"
#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    client_options_t options;
    const char *error = NULL;
    int result = client_parse_options(argc, argv, &options, &error);
    if (result == CLIENT_PARSE_HELP) {
        return fputs(client_usage(), stdout) == EOF || fflush(stdout) == EOF
            ? EXIT_FAILURE : EXIT_SUCCESS;
    }
    if (result != CLIENT_PARSE_OK) {
        fprintf(stderr, "%s\n%s", error, client_usage());
        return EXIT_FAILURE;
    }
    if (client_config_load(options.config_path, &options.deployment, &error) != CLIENT_PARSE_OK) {
        fprintf(stderr, "%s\n", error);
        return EXIT_FAILURE;
    }
    char password[CLIENT_PASSWORD_MAX + 1] = {0};
    int password_result = client_read_password("Password: ", password, sizeof(password));
    /* There is no network consumer yet. Discard immediately, on every result. */
    OPENSSL_cleanse(password, sizeof(password));
    if (password_result != CLIENT_PASSWORD_OK) {
        const char *message = "Unable to read password";
        if (password_result == CLIENT_PASSWORD_NOT_TERMINAL) message = "Password input requires an interactive terminal";
        else if (password_result == CLIENT_PASSWORD_EMPTY) message = "Password must not be empty";
        else if (password_result == CLIENT_PASSWORD_TOO_LONG) message = "Password exceeds the local 4096-byte limit";
        else if (password_result == CLIENT_PASSWORD_INTERRUPTED) message = "Password input interrupted";
        fprintf(stderr, "%s\n", message);
        return EXIT_FAILURE;
    }
    /* Success here means valid configuration, never a completed remote command. */
    if (puts("Configuration valid. Client networking is not implemented; no operation performed.") == EOF ||
        fflush(stdout) == EOF) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
