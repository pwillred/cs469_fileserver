/*
 * CS 469
 * Pure client argument tests. No DNS, sockets, TLS, files or server state used.
 */
#include "../client_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static unsigned int cases = 0;

static void base_args(char **args) {
    char *base[] = {
        "client", "--primary-host", "primary.invalid", "--primary-port", "1234",
        "--replica-host", "replica.invalid", "--replica-port", "5678",
        "--ca", "/nonexistent/ca.pem", "--username", "student", "list",
        NULL, NULL, NULL, NULL
    };
    memcpy(args, base, sizeof(base));
}

static client_options_t parse(int argc, char **args, int expected) {
    client_options_t options = {0};
    const char *error = "old diagnostic";
    char *before[18];
    memcpy(before, args, sizeof(before));
    CHECK(client_parse_options(argc, args, &options, &error) == expected);
    CHECK(memcmp(args, before, sizeof(before)) == 0);
    if (expected == CLIENT_PARSE_ERROR) {
        CHECK(error != NULL && error[0] != '\0');
        CHECK(options.primary.host == NULL && options.primary.port == 0);
        CHECK(options.replica.host == NULL && options.replica.port == 0);
        CHECK(options.ca_file == NULL && options.username == NULL);
        CHECK(options.local_path == NULL && options.remote_name == NULL);
    } else {
        CHECK(error == NULL);
    }
    ++cases;
    return options;
}

int main(void) {
    char *args[18];
    base_args(args);
    client_options_t options = parse(14, args, CLIENT_PARSE_OK);
    CHECK(options.command == CLIENT_COMMAND_LIST);
    CHECK(strcmp(options.primary.host, "primary.invalid") == 0 && options.primary.port == 1234);
    CHECK(strcmp(options.replica.host, "replica.invalid") == 0 && options.replica.port == 5678);
    CHECK(options.ca_file == args[10] && options.username == args[12]);
    CHECK(options.local_path == NULL && options.remote_name == NULL);
    args[13] = "upload"; args[14] = "/nonexistent/source"; args[15] = "remote.txt";
    options = parse(16, args, CLIENT_PARSE_OK);
    CHECK(options.command == CLIENT_COMMAND_UPLOAD);
    CHECK(options.local_path == args[14] && options.remote_name == args[15]);
    args[13] = "download"; args[14] = "remote.txt"; args[15] = "/nonexistent/destination";
    options = parse(16, args, CLIENT_PARSE_OK);
    CHECK(options.command == CLIENT_COMMAND_DOWNLOAD);
    CHECK(options.remote_name == args[14] && options.local_path == args[15]);
    args[13] = "delete";
    options = parse(15, args, CLIENT_PARSE_OK);
    CHECK(options.command == CLIENT_COMMAND_DELETE && options.remote_name == args[14]);
    CHECK(options.local_path == NULL);

    char *bad_ports[] = {"0", "65536", "999999999999999999999999999", "abc", "12x",
        "-1", "+1", "1.5", " 80", "80 ", ""};
    for (int endpoint = 4; endpoint <= 8; endpoint += 4) {
        for (size_t i = 0; i < sizeof(bad_ports) / sizeof(bad_ports[0]); ++i) {
            base_args(args); args[endpoint] = bad_ports[i];
            parse(14, args, CLIENT_PARSE_ERROR);
        }
        base_args(args); args[endpoint] = "1";
        options = parse(14, args, CLIENT_PARSE_OK);
        CHECK((endpoint == 4 ? options.primary.port : options.replica.port) == 1);
        args[endpoint] = "65535";
        options = parse(14, args, CLIENT_PARSE_OK);
        CHECK((endpoint == 4 ? options.primary.port : options.replica.port) == 65535);
        args[endpoint] = "00080";
        options = parse(14, args, CLIENT_PARSE_OK);
        CHECK((endpoint == 4 ? options.primary.port : options.replica.port) == 80);
    }
    for (int value = 2; value <= 12; value += 2) {
        base_args(args); args[value] = "";
        parse(14, args, CLIENT_PARSE_ERROR);
        base_args(args);
        /* Remove each required option/value pair. */
        for (int i = value - 1; i < 12; ++i) {
            args[i] = args[i + 2];
        }
        parse(12, args, CLIENT_PARSE_ERROR);
        base_args(args);
        /* End the invocation immediately after an option name. */
        parse(value, args, CLIENT_PARSE_ERROR);
        base_args(args); args[value] = "--username";
        parse(14, args, CLIENT_PARSE_ERROR);
    }
    for (int host = 2; host <= 6; host += 4) {
        base_args(args); args[host] = "host name";
        parse(14, args, CLIENT_PARSE_ERROR);
        args[host] = "host\nname";
        parse(14, args, CLIENT_PARSE_ERROR);
        args[host] = "2001:db8::1";
        parse(14, args, CLIENT_PARSE_OK);
    }
    char *commands[] = {"list", "upload", "download", "delete"};
    int operands[] = {0, 2, 2, 1};
    for (size_t i = 0; i < 4; ++i) {
        base_args(args); args[13] = commands[i];
        args[14] = "first"; args[15] = "second"; args[16] = "extra";
        parse(15 + operands[i], args, CLIENT_PARSE_ERROR);
        if (operands[i] != 0) {
            parse(13 + operands[i], args, CLIENT_PARSE_ERROR);
        }
    }
    base_args(args); parse(13, args, CLIENT_PARSE_ERROR);
    args[13] = "unknown"; parse(14, args, CLIENT_PARSE_ERROR);
    args[13] = "LIST"; parse(14, args, CLIENT_PARSE_ERROR);
    base_args(args); args[1] = "--unknown"; parse(14, args, CLIENT_PARSE_ERROR);
    args[1] = "--password"; parse(14, args, CLIENT_PARSE_ERROR);
    args[1] = "--password=secret"; parse(14, args, CLIENT_PARSE_ERROR);
    base_args(args); args[11] = "--ca"; parse(14, args, CLIENT_PARSE_ERROR);
    base_args(args); args[13] = "list"; args[14] = "--password"; args[15] = "secret";
    parse(16, args, CLIENT_PARSE_ERROR);
    char *bad_names[] = {"", ".", "..", "a/b", "a\\b"};
    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); ++i) {
        base_args(args); args[13] = "delete"; args[14] = bad_names[i];
        parse(15, args, CLIENT_PARSE_ERROR);
    }
    base_args(args); args[13] = "upload"; args[14] = ""; args[15] = "remote";
    parse(16, args, CLIENT_PARSE_ERROR);
    args[13] = "download"; args[14] = "remote"; args[15] = "";
    parse(16, args, CLIENT_PARSE_ERROR);
    base_args(args); args[1] = "--help";
    parse(2, args, CLIENT_PARSE_HELP);
    parse(1, args, CLIENT_PARSE_ERROR);
    base_args(args); args[2] = NULL; parse(14, args, CLIENT_PARSE_ERROR);
    const char *error = NULL;
    CHECK(client_parse_options(0, args, &options, &error) == CLIENT_PARSE_ERROR && error != NULL);
    CHECK(client_parse_options(14, NULL, &options, NULL) == CLIENT_PARSE_ERROR);
    CHECK(client_parse_options(14, args, NULL, NULL) == CLIENT_PARSE_ERROR);
    base_args(args);
    CHECK(client_parse_options(14, args, &options, NULL) == CLIENT_PARSE_OK);
    /* Every call uses fresh state: parsing remains repeatable in one process. */
    parse(14, args, CLIENT_PARSE_OK);
    printf("PASS: %u parser cases plus null/API checks; no files or networking used\n", cases);
    return EXIT_SUCCESS;
}
