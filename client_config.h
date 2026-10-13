/*
 * CS 469
 * Client CLI configuration, independent of server and wire-protocol definitions.
 */
#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stdint.h>

typedef struct {
    const char *host;
    uint16_t port;
} client_endpoint_t;

typedef enum {
    CLIENT_COMMAND_LIST,
    CLIENT_COMMAND_UPLOAD,
    CLIENT_COMMAND_DOWNLOAD,
    CLIENT_COMMAND_DELETE
} client_command_t;

typedef struct {
    client_endpoint_t primary;
    client_endpoint_t replica;
    const char *ca_file;
    const char *username;
    client_command_t command;
    const char *local_path;
    const char *remote_name;
} client_options_t;

enum {
    CLIENT_PARSE_OK = 0,
    CLIENT_PARSE_ERROR = 1,
    CLIENT_PARSE_HELP = 2
};

/*
 * Syntax: six required --name value options before a lowercase command; see
 * client_usage(). Both endpoints are required, including for write commands.
 * Duplicates, unknown options, --name=value syntax and extra operands are errors.
 * --help is supported only as the sole argument. No defaults are inferred.
 *
 * Returns OK, ERROR or HELP. On ERROR/HELP, *options is zeroed when non-NULL.
 * NULL options/argv, argc < 1 or NULL entries within argc are invalid. If error
 * is non-NULL, *error receives a static diagnostic on failure, else NULL.
 * No diagnostics echo argument contents. No argument or argument array changes.
 *
 * On success, string pointers borrow argv storage, which must outlive options.
 * Hosts are nonempty, without ASCII whitespace/control bytes; ports are decimal
 * digits only, 1-65535. CA path, username and local paths must be nonempty.
 * Remote names must be nonempty and not '.', '..', or contain '/' or '\\'.
 * No filesystem checks, username policy, protocol length rules or DNS lookups
 * occur here. All strings are C strings; no password is accepted or retained.
 *
 * Future transport must verify certificates against ca_file and verify each
 * endpoint's identity using its host (with SNI where appropriate). There is no
 * insecure mode or client certificate. Secure password prompting is deferred.
 * Future LIST/DOWNLOAD: primary first, replica only for eligible availability
 * failures. UPLOAD/DELETE: primary only. This module implements no routing.
 */
int client_parse_options(int argc, char *const argv[], client_options_t *options,
                         const char **error);

/* Static usage text; the caller must not free or modify it. */
const char *client_usage(void);

#endif /* CLIENT_CONFIG_H */
