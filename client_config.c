/*
 * CS 469
 * Reentrant, allocation-free CLI parser. No protocol, TLS or networking code.
 */
#include "client_config.h"

#include <stddef.h>
#include <string.h>

const char *client_usage(void) {
    return "Usage:\n"
        "  client --primary-host HOST --primary-port PORT\n"
        "         --replica-host HOST --replica-port PORT\n"
        "         --ca FILE --username USER COMMAND [ARGUMENTS]\n"
        "  client --help\n\n"
        "Commands:\n"
        "  list\n"
        "  upload LOCAL_FILE REMOTE_NAME\n"
        "  download REMOTE_NAME LOCAL_FILE\n"
        "  delete REMOTE_NAME\n\n"
        "All six options are required and must precede the command.\n"
        "Ports: decimal 1-65535. Password arguments are not supported.\n"
        "Foundation only: no files are opened and no network operation occurs.\n";
}

static int fail(const char **error, const char *message) {
    if (error != NULL) {
        *error = message;
    }
    return CLIENT_PARSE_ERROR;
}

static int valid_host(const char *host) {
    for (const unsigned char *p = (const unsigned char *)host; *p != '\0'; ++p) {
        if (*p <= 32 || *p == 127) {
            return 0;
        }
    }
    return host[0] != '\0';
}

static int parse_port(const char *text, uint16_t *port) {
    unsigned long value = 0;
    if (text[0] == '\0') {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        value = value * 10 + (*p - '0');
        if (value > 65535) {
            return 0;
        }
    }
    *port = (uint16_t)value;
    return value != 0;
}

static int valid_remote_name(const char *name) {
    return name[0] != '\0' && strcmp(name, ".") != 0 && strcmp(name, "..") != 0 &&
        strchr(name, '/') == NULL && strchr(name, '\\') == NULL;
}

int client_parse_options(int argc, char *const argv[], client_options_t *options,
                         const char **error) {
    if (error != NULL) {
        *error = NULL;
    }
    if (options != NULL) {
        *options = (client_options_t){0};
    }
    if (options == NULL || argv == NULL || argc < 1) {
        return fail(error, "Invalid parser arguments");
    }
    for (int i = 0; i < argc; ++i) {
        if (argv[i] == NULL) {
            return fail(error, "Invalid argument entry");
        }
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        return CLIENT_PARSE_HELP;
    }

    static const char *const names[] = {
        "--primary-host", "--primary-port", "--replica-host", "--replica-port",
        "--ca", "--username"
    };
    const char *values[6] = {0};
    int next = 1;
    while (next < argc && argv[next][0] == '-') {
        size_t option;
        for (option = 0; option < 6; ++option) {
            if (strcmp(argv[next], names[option]) == 0) {
                break;
            }
        }
        if (option == 6) {
            return fail(error, "Unknown option (password options are not supported)");
        }
        if (values[option] != NULL) {
            return fail(error, "Duplicate option");
        }
        if (next + 1 >= argc || argv[next + 1][0] == '\0' ||
            strncmp(argv[next + 1], "--", 2) == 0) {
            return fail(error, "Missing or empty option value");
        }
        values[option] = argv[next + 1];
        next += 2;
    }
    for (size_t i = 0; i < 6; ++i) {
        if (values[i] == NULL) {
            return fail(error, "Both endpoints, CA path and username are required");
        }
    }
    client_options_t parsed = {0};
    if (!valid_host(values[0]) || !valid_host(values[2])) {
        return fail(error, "Hosts must be nonempty without whitespace/control characters");
    }
    if (!parse_port(values[1], &parsed.primary.port) ||
        !parse_port(values[3], &parsed.replica.port)) {
        return fail(error, "Ports must contain decimal digits and be in range 1-65535");
    }
    parsed.primary.host = values[0];
    parsed.replica.host = values[2];
    parsed.ca_file = values[4];
    parsed.username = values[5];
    if (next == argc) {
        return fail(error, "Missing command");
    }
    const char *command = argv[next++];
    int required;
    if (strcmp(command, "list") == 0) {
        parsed.command = CLIENT_COMMAND_LIST;
        required = 0;
    } else if (strcmp(command, "upload") == 0) {
        parsed.command = CLIENT_COMMAND_UPLOAD;
        required = 2;
    } else if (strcmp(command, "download") == 0) {
        parsed.command = CLIENT_COMMAND_DOWNLOAD;
        required = 2;
    } else if (strcmp(command, "delete") == 0) {
        parsed.command = CLIENT_COMMAND_DELETE;
        required = 1;
    } else {
        return fail(error, "Unknown command");
    }
    if (argc - next != required) {
        return fail(error, "Incorrect number of command arguments");
    }
    if (parsed.command == CLIENT_COMMAND_UPLOAD) {
        parsed.local_path = argv[next];
        parsed.remote_name = argv[next + 1];
    } else if (parsed.command == CLIENT_COMMAND_DOWNLOAD) {
        parsed.remote_name = argv[next];
        parsed.local_path = argv[next + 1];
    } else if (parsed.command == CLIENT_COMMAND_DELETE) {
        parsed.remote_name = argv[next];
    }
    if (parsed.local_path != NULL && parsed.local_path[0] == '\0') {
        return fail(error, "Local path must not be empty");
    }
    if (parsed.remote_name != NULL && !valid_remote_name(parsed.remote_name)) {
        return fail(error, "Remote name must be a nonempty filename without path separators");
    }
    *options = parsed;
    return CLIENT_PARSE_OK;
}
