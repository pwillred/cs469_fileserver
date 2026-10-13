/*
 * CS 469
 * CLI parsing and bounded deployment-file loading. No protocol or networking.
 */
#include "client_config.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

const char *client_usage(void) {
    return "Usage:\n"
        "  client [--config FILE] --username USER COMMAND [ARGUMENTS]\n"
        "  client --help\n\n"
        "Commands:\n"
        "  list\n"
        "  upload LOCAL_FILE REMOTE_NAME\n"
        "  download REMOTE_NAME LOCAL_FILE\n"
        "  delete REMOTE_NAME\n\n"
        "Options must precede the command; default configuration: client.conf.\n"
        "Topology belongs in configuration. Password arguments are unsupported.\n"
        "Foundation only: no network operation occurs.\n";
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

    client_options_t parsed = {0};
    int next = 1;
    while (next < argc && argv[next][0] == '-') {
        const char **slot;
        if (strcmp(argv[next], "--config") == 0) slot = &parsed.config_path;
        else if (strcmp(argv[next], "--username") == 0) slot = &parsed.username;
        else return fail(error, "Unknown option; topology/password CLI options are unsupported");
        if (*slot != NULL) return fail(error, "Duplicate option");
        if (next + 1 >= argc || argv[next + 1][0] == '\0' ||
            strncmp(argv[next + 1], "--", 2) == 0) {
            return fail(error, "Missing or empty option value");
        }
        *slot = argv[next + 1];
        next += 2;
    }
    if (parsed.username == NULL) return fail(error, "--username is required");
    if (parsed.config_path == NULL) parsed.config_path = CLIENT_DEFAULT_CONFIG;
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

/* Locale-independent whitespace keeps the configuration format predictable. */
static int whitespace(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

static char *trim(char *text) {
    while (whitespace((unsigned char)*text)) ++text;
    size_t n = strlen(text);
    while (n > 0 && whitespace((unsigned char)text[n - 1])) text[--n] = '\0';
    return text;
}

int client_config_load(const char *path, client_deployment_config_t *config,
                        const char **error) {
    if (error != NULL) *error = NULL;
    if (config != NULL) *config = (client_deployment_config_t){0};
    if (path == NULL || path[0] == '\0' || config == NULL)
        return fail(error, "Invalid configuration path or output");
    FILE *file = fopen(path, "r");
    if (file == NULL) return fail(error, "Unable to open client configuration file");
    static const char *const keys[] = {
        "primary_host", "primary_port", "replica_host", "replica_port", "ca_file"
    };
    client_deployment_config_t loaded = {0};
    unsigned int seen = 0;
    const char *problem = NULL;
    char line[CLIENT_CONFIG_LINE_MAX + 1];
    for (;;) {
        size_t length = 0;
        int c;
        /* Byte reads detect embedded NULs and enforce bounds even on comments. */
        while ((c = fgetc(file)) != EOF && c != '\n') {
            if (c == 0 || length == CLIENT_CONFIG_LINE_MAX) {
                problem = "Configuration line contains NUL or exceeds 2048 bytes";
                break;
            }
            line[length++] = (char)c;
        }
        if (problem != NULL) break;
        if (ferror(file)) { problem = "Unable to read client configuration"; break; }
        line[length] = '\0';
        char *key = trim(line);
        if (*key != '\0' && *key != '#') {
            char *equals = strchr(key, '=');
            if (equals == NULL || strchr(equals + 1, '=') != NULL) {
                problem = "Configuration lines require exactly one '='"; break;
            }
            *equals = '\0';
            key = trim(key);
            char *value = trim(equals + 1);
            size_t index;
            for (index = 0; index < 5 && strcmp(key, keys[index]) != 0; ++index) {}
            if (index == 5) { problem = "Unknown configuration key"; break; }
            if (seen & (1u << index)) { problem = "Duplicate configuration key"; break; }
            size_t n = strlen(value);
            if (n == 0 || n > CLIENT_CONFIG_VALUE_MAX) {
                problem = "Configuration value is empty or exceeds 1023 bytes"; break;
            }
            if (index == 0 || index == 2) {
                if (n > CLIENT_HOST_MAX || !valid_host(value)) {
                    problem = "Host must be 1-255 bytes without whitespace/control characters"; break;
                }
                strcpy(index == 0 ? loaded.primary.host : loaded.replica.host, value);
            } else if (index == 1 || index == 3) {
                if (!parse_port(value, index == 1 ? &loaded.primary.port : &loaded.replica.port)) {
                    problem = "Configuration ports must be decimal 1-65535"; break;
                }
            } else {
                strcpy(loaded.ca_file, value);
            }
            seen |= 1u << index;
        }
        if (c == EOF) break;
    }
    if (fclose(file) != 0 && problem == NULL) problem = "Unable to close client configuration";
    if (problem == NULL && seen != 31u) problem = "Missing required client configuration keys";
    if (problem != NULL) return fail(error, problem);
    *config = loaded;
    return CLIENT_PARSE_OK;
}
