/*
 * CS 469
 * Logical file-service configuration, independent of the wire protocol.
 */
#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H
#include <stdint.h>

#define CLIENT_HOST_MAX 255
#define CLIENT_CONFIG_VALUE_MAX 1023
#define CLIENT_CONFIG_LINE_MAX 2048
#define CLIENT_DEFAULT_CONFIG "client.conf"

typedef struct {
    char host[CLIENT_HOST_MAX + 1];
    uint16_t port;
} client_endpoint_t;

typedef struct {
    client_endpoint_t primary;
    client_endpoint_t replica;
    char ca_file[CLIENT_CONFIG_VALUE_MAX + 1];
} client_deployment_config_t;

typedef enum {
    CLIENT_COMMAND_LIST,
    CLIENT_COMMAND_UPLOAD,
    CLIENT_COMMAND_DOWNLOAD,
    CLIENT_COMMAND_DELETE
} client_command_t;

typedef struct {
    client_deployment_config_t deployment;
    const char *config_path;
    const char *username;
    client_command_t command;
    const char *local_path;
    const char *remote_name;
} client_options_t;

enum { CLIENT_PARSE_OK = 0, CLIENT_PARSE_ERROR = 1, CLIENT_PARSE_HELP = 2 };

/*
 * Pure CLI parsing: [--config FILE] --username USER COMMAND [ARGUMENTS].
 * Options precede the command; unknown/duplicate options and extra operands
 * fail. --help is accepted only alone. Old topology/password flags are rejected.
 * config_path defaults to client.conf relative to the process working directory.
 * Strings borrow argv storage (except the static default path); argv must outlive
 * options. deployment is zero until separately loaded. No passwords are stored.
 * Username/local paths must be nonempty. Remote names cannot be empty, '.', '..'
 * or contain '/' or '\\'. No protocol-length or account-policy validation yet.
 * Returns OK/ERROR/HELP. Output is zeroed on failure/help. NULL options/argv,
 * argc < 1 or NULL argv entries within argc fail. Optional error receives a
 * static diagnostic on failure, NULL otherwise; diagnostics never echo values.
 */
int client_parse_options(int argc, char *const argv[], client_options_t *options,
                         const char **error);

/*
 * Load all five required key=value entries: primary_host, primary_port,
 * replica_host, replica_port, ca_file. Blank lines and trimmed #-comment lines
 * are allowed. ASCII edge whitespace is trimmed; no quoting, escaping, inline
 * comments, substitutions or extra '=' characters. Ports are decimal 1-65535.
 * Unknown/duplicate/missing keys, empty values, NUL bytes and excess lengths
 * fail. Host limit 255 bytes, other values 1023, lines 2048 excluding '\n'.
 * Hosts cannot contain ASCII whitespace/control bytes. No DNS/TLS is attempted.
 * Relative CA paths are relative to the working directory, not the config file.
 * CA existence/trust validation is deferred to TLS implementation.
 * Returns OK/ERROR; config owns all strings by value and is zeroed on failure.
 * NULL/empty path or NULL output fails. Optional error semantics match parser.
 * All file handles are closed. No global state or heap ownership is exposed.
 *
 * Users address one logical service. Deployment topology stays internal:
 * future LIST/DOWNLOAD use primary first with automatic eligible read failover;
 * writes stay primary-only. Loading configuration does not implement routing.
 */
int client_config_load(const char *path, client_deployment_config_t *config,
                        const char **error);
const char *client_usage(void);
#endif /* CLIENT_CONFIG_H */
