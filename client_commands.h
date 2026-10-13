#ifndef CLIENT_COMMANDS_H
#define CLIENT_COMMANDS_H
#include "client_protocol.h"
#include <stdio.h>
typedef enum {
    CLIENT_RESULT_OK, CLIENT_RESULT_LOCAL, CLIENT_RESULT_TRANSPORT,
    CLIENT_RESULT_PROTOCOL, CLIENT_RESULT_STATUS
} client_result_kind_t;
typedef struct {
    client_result_kind_t kind;
    int transport;
    client_status_t status;
    const char *message;
} client_command_result_t;
/* One primary connection, no retries. LIST goes to output (empty list: nothing).
 * Takes a writable password allocation of password_capacity bytes, including NUL.
 * Cleanses its ENTIRE capacity on every return, including validation failures.
 * options borrows argv; password must not alias options or output storage.
 * Caller handles prompt failures before invoking this function. No secrets stored.
 * Result retains transport/security vs application vs local/protocol distinctions.
 * Download never replaces a destination; publication uses atomic linkat, then
 * removes its temporary sibling, rather than POSIX rename (which overwrites).
 */
client_command_result_t client_execute(const client_options_t *options,
    char *password, size_t password_capacity, FILE *output);
#endif
