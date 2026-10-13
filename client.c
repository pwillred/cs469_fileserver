/*
 * CS 469
 * Client CLI foundation. Validates local configuration only; does not execute
 * file operations. Networking and secure password prompting are future work.
 */
#include "client_config.h"

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
    /* Success here means valid configuration, never a completed remote command. */
    if (puts("Configuration valid. Client networking is not implemented; no operation performed.") == EOF ||
        fflush(stdout) == EOF) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
