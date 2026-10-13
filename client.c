/*
 * CS 469
 * Primary-only file-service client using the frozen working wire contract.
 */
#include "client_config.h"
#include "client_password.h"
#include "client_commands.h"
#include <signal.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    /* Turn output pipe failures into errors so password cleanup can run. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return EXIT_FAILURE;
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
    if (password_result != CLIENT_PASSWORD_OK) {
        OPENSSL_cleanse(password, sizeof(password));
        const char *message = "Unable to read password";
        if (password_result == CLIENT_PASSWORD_NOT_TERMINAL) message = "Password input requires an interactive terminal";
        else if (password_result == CLIENT_PASSWORD_EMPTY) message = "Password must not be empty";
        else if (password_result == CLIENT_PASSWORD_TOO_LONG) message = "Password exceeds the local 4096-byte limit";
        else if (password_result == CLIENT_PASSWORD_INTERRUPTED) message = "Password input interrupted";
        fprintf(stderr, "%s\n", message);
        return EXIT_FAILURE;
    }
    client_command_result_t command_result = client_execute(&options, password, sizeof(password), stdout);
    /* client_execute cleanses the entire password allocation on every return. */
    if (command_result.kind != CLIENT_RESULT_OK) {
        fprintf(stderr, "%s\n", command_result.message);
        return EXIT_FAILURE;
    }
    if (options.command != CLIENT_COMMAND_LIST &&
        (puts(options.command == CLIENT_COMMAND_UPLOAD ? "Upload complete." :
              options.command == CLIENT_COMMAND_DOWNLOAD ? "Download complete." : "Delete complete.") == EOF ||
         fflush(stdout) == EOF)) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
