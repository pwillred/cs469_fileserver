/*
 * CS 469
 * Deployment configuration and independent CLI tests; no networking required.
 */
#define _POSIX_C_SOURCE 200809L
#include "../client_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d\n",__LINE__); goto cleanup; } } while (0)
static unsigned int cases;
static const char *const keys[] = {"primary_host", "primary_port", "replica_host", "replica_port", "ca_file"};
static const char *const values[] = {"primary.example", "4433", "replica.example", "4434", "certs/ca.pem"};

static int load_text(const char *path, const char *text, size_t size, int expected) {
    FILE *file = fopen(path, "wb");
    if (file == NULL) return 0;
    int written = fwrite(text, 1, size, file) == size;
    if (fclose(file) != 0 || !written) return 0;
    client_deployment_config_t config;
    memset(&config, 'x', sizeof(config));
    const char *error = NULL;
    int result = client_config_load(path, &config, &error);
    ++cases;
    if (result != expected) return 0;
    if (result == CLIENT_PARSE_ERROR) {
        return error != NULL && config.primary.host[0] == 0 && config.replica.host[0] == 0 &&
            config.primary.port == 0 && config.replica.port == 0 && config.ca_file[0] == 0;
    }
    return error == NULL && config.primary.host[0] != 0 && config.replica.host[0] != 0;
}

/* Build fixtures with one key missing/replaced, retaining every other key. */
static int fixture(const char *path, int omit, int replace, const char *replacement, int expected) {
    char text[8192];
    size_t used = 0;
    for (int i = 0; i < 5; ++i) {
        if (i == omit) continue;
        int n = snprintf(text + used, sizeof(text) - used, "%s=%s\n", keys[i],
                         i == replace ? replacement : values[i]);
        if (n < 0 || (size_t)n >= sizeof(text) - used) return 0;
        used += (size_t)n;
    }
    return load_text(path, text, used, expected);
}

static int parse(int argc, char **argv, int expected) {
    client_options_t options;
    const char *error = NULL;
    int result = client_parse_options(argc, argv, &options, &error);
    ++cases;
    return result == expected && (expected == CLIENT_PARSE_ERROR ? error != NULL : error == NULL) &&
        (expected == CLIENT_PARSE_OK || options.config_path == NULL);
}

int main(void) {
    char path[] = "/tmp/cs469-client-config-XXXXXX";
    int fd = mkstemp(path);
    int result = EXIT_FAILURE;
    CHECK(fd >= 0);
    int closed = close(fd);
    fd = -1;
    CHECK(closed == 0);
    CHECK(fixture(path, -1, -1, NULL, CLIENT_PARSE_OK));
    client_deployment_config_t config;
    const char *error;
    CHECK(client_config_load(path, &config, &error) == CLIENT_PARSE_OK);
    CHECK(strcmp(config.primary.host, "primary.example") == 0 && config.primary.port == 4433);
    CHECK(strcmp(config.replica.host, "replica.example") == 0 && config.replica.port == 4434);
    CHECK(strcmp(config.ca_file, "certs/ca.pem") == 0);
    const char *formatted = "\n  # comment\r\n primary_host = server.example \r\nprimary_port = 1\n\t\n"
        "replica_host=::1\nreplica_port=65535\n ca_file = path with spaces/ca.pem ";
    CHECK(load_text(path, formatted, strlen(formatted), CLIENT_PARSE_OK));
    CHECK(client_config_load(path, &config, &error) == CLIENT_PARSE_OK);
    CHECK(config.primary.port == 1 && config.replica.port == 65535);
    CHECK(strcmp(config.primary.host, "server.example") == 0 && strcmp(config.replica.host, "::1") == 0);
    CHECK(strcmp(config.ca_file, "path with spaces/ca.pem") == 0);
    for (int i = 0; i < 5; ++i) {
        CHECK(fixture(path, i, -1, NULL, CLIENT_PARSE_ERROR));
        CHECK(fixture(path, -1, i, "", CLIENT_PARSE_ERROR));
    }
    const char *bad_ports[] = {"0", "65536", "abc", "-1", "+1", "1.5", "1 2", "999999999999999999999"};
    for (int port = 1; port <= 3; port += 2) {
        for (size_t i = 0; i < sizeof(bad_ports)/sizeof(bad_ports[0]); ++i)
            CHECK(fixture(path, -1, port, bad_ports[i], CLIENT_PARSE_ERROR));
        CHECK(fixture(path, -1, port, "00001", CLIENT_PARSE_OK));
        CHECK(fixture(path, -1, port, "65535", CLIENT_PARSE_OK));
    }
    for (int host = 0; host <= 2; host += 2)
        CHECK(fixture(path, -1, host, "bad host", CLIENT_PARSE_ERROR));
    const char *bad[] = {"unknown=x\n", "primary_host=a\nprimary_host=b\n", "broken\n", "=x\n", "primary_host=a=b\n", "", "# only comment\n"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        CHECK(load_text(path, bad[i], strlen(bad[i]), CLIENT_PARSE_ERROR));
    char huge[CLIENT_CONFIG_LINE_MAX + 2];
    memset(huge, 'a', sizeof(huge)); huge[sizeof(huge)-1] = 0;
    CHECK(load_text(path, huge, strlen(huge), CLIENT_PARSE_ERROR));
    huge[CLIENT_CONFIG_VALUE_MAX + 1] = 0;
    CHECK(fixture(path, -1, 4, huge, CLIENT_PARSE_ERROR));
    huge[CLIENT_CONFIG_VALUE_MAX] = 0;
    CHECK(fixture(path, -1, 4, huge, CLIENT_PARSE_OK));
    huge[CLIENT_HOST_MAX + 1] = 0;
    CHECK(fixture(path, -1, 0, huge, CLIENT_PARSE_ERROR));
    huge[CLIENT_HOST_MAX] = 0;
    CHECK(fixture(path, -1, 0, huge, CLIENT_PARSE_OK));
    CHECK(load_text(path, "primary_host=a\0b\n", 17, CLIENT_PARSE_ERROR));
    CHECK(client_config_load(NULL, &config, &error) == CLIENT_PARSE_ERROR);
    CHECK(client_config_load("", &config, NULL) == CLIENT_PARSE_ERROR);
    CHECK(client_config_load(path, NULL, &error) == CLIENT_PARSE_ERROR);
    CHECK(unlink(path) == 0);
    CHECK(client_config_load(path, &config, &error) == CLIENT_PARSE_ERROR);

    char *args[] = {"client", "--username", "alice", "list", "local", "remote", "extra"};
    client_options_t options;
    CHECK(client_parse_options(4, args, &options, &error) == CLIENT_PARSE_OK);
    CHECK(strcmp(options.config_path, "client.conf") == 0 && options.username == args[2]);
    CHECK(options.deployment.primary.host[0] == 0);
    CHECK(options.command == CLIENT_COMMAND_LIST);
    const char *commands[] = {"list", "upload", "download", "delete"};
    int counts[] = {4,6,6,5};
    for (int i = 0; i < 4; ++i) {
        args[3] = (char *)commands[i];
        CHECK(parse(counts[i], args, CLIENT_PARSE_OK));
        CHECK(client_parse_options(counts[i], args, &options, NULL) == CLIENT_PARSE_OK);
        CHECK(options.command == (client_command_t)i);
        if (i == 1) CHECK(options.local_path == args[4] && options.remote_name == args[5]);
        if (i == 2) CHECK(options.remote_name == args[4] && options.local_path == args[5]);
        if (i == 3) CHECK(options.remote_name == args[4] && options.local_path == NULL);
        CHECK(parse(counts[i] + 1, args, CLIENT_PARSE_ERROR));
        if (i != 0) CHECK(parse(counts[i] - 1, args, CLIENT_PARSE_ERROR));
    }
    char *custom[] = {"client", "--config", path, "--username", "alice", "list"};
    /* Pure parsing succeeds even though this custom file has been removed. */
    CHECK(client_parse_options(6, custom, &options, &error) == CLIENT_PARSE_OK);
    CHECK(options.config_path == path);
    const char *unsupported[] = {"--primary-host", "--primary-port", "--replica-host", "--replica-port", "--ca", "--password", "--unknown"};
    for (size_t i = 0; i < sizeof(unsupported)/sizeof(unsupported[0]); ++i) {
        custom[1] = (char *)unsupported[i];
        CHECK(parse(6, custom, CLIENT_PARSE_ERROR));
    }
    custom[1] = "--username"; CHECK(parse(6, custom, CLIENT_PARSE_ERROR));
    custom[1] = "--config"; custom[2] = ""; CHECK(parse(6, custom, CLIENT_PARSE_ERROR));
    custom[2] = "--username"; CHECK(parse(6, custom, CLIENT_PARSE_ERROR));
    CHECK(parse(2, custom, CLIENT_PARSE_ERROR));
    args[3] = "unknown"; CHECK(parse(4, args, CLIENT_PARSE_ERROR));
    CHECK(parse(3, args, CLIENT_PARSE_ERROR));
    args[1] = "--config"; CHECK(parse(4, args, CLIENT_PARSE_ERROR));
    args[1] = "--help"; CHECK(parse(2, args, CLIENT_PARSE_HELP));
    CHECK(parse(1, args, CLIENT_PARSE_ERROR));
    CHECK(client_parse_options(0, args, &options, NULL) == CLIENT_PARSE_ERROR);
    CHECK(client_parse_options(4, NULL, &options, NULL) == CLIENT_PARSE_ERROR);
    CHECK(client_parse_options(4, args, NULL, NULL) == CLIENT_PARSE_ERROR);
    result = EXIT_SUCCESS;
cleanup:
    if (fd >= 0) close(fd);
    if (access(path, F_OK) == 0 && unlink(path) != 0) result = EXIT_FAILURE;
    if (result == EXIT_SUCCESS) printf("PASS: %u config/parser cases plus structure/API checks; temporary file removed\n", cases);
    return result;
}
