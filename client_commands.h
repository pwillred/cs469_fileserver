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
/* Primary first. LIST/DOWNLOAD may try replica exactly once for RESOLVE_ERROR,
 * CONNECT_ERROR, TIMEOUT, IO_ERROR or EOF before the initial valid status byte.
 * Any status, security/configuration, protocol or local failure forbids failover.
 * After OK, all length/count/payload failures are final. Writes stay primary-only.
 * No retry loop/backoff. Routing diagnostics go to stderr, LIST to output
 * (empty list: nothing). Both endpoints come from options.deployment.
 * Takes a writable password allocation of password_capacity bytes, including NUL.
 * Reuses the same password for both attempts, then cleanses its ENTIRE capacity
 * on every return, including validation failures. Never reprompts.
 * options borrows argv; password must not alias options or output storage.
 * Caller handles prompt failures before invoking this function. No secrets stored.
 * Result retains transport/security vs application vs local/protocol distinctions.
 * Download never replaces a destination; publication uses atomic linkat, then
 * removes its temporary sibling, rather than POSIX rename (which overwrites).
 */
client_command_result_t client_execute(const client_options_t *options,
    char *password, size_t password_capacity, FILE *output);
#endif
