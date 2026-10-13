/* Deterministic command-layer routing tests. Transport double injects resolver,
 * connect timeout and I/O results without relying on DNS or a blackholed route.
 * Real TLS/CLI behavior is tested separately by test_client_integration.py. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "../client_commands.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL routing line %d\n", __LINE__); exit(1); } } while (0)
struct client_connection { int index, reads; };
struct outcome { int error, phase, status; }; /* open=0, write=1, status=2, after OK=3 */
static struct outcome outcomes[2];
static struct client_connection handles[2];
static int opens, live, password_writes, cases;
static const char *current_password;

int client_connection_open(const client_endpoint_t *endpoint, const char *ca, client_connection_t **out) {
    CHECK(opens < 2 && live == 0);
    CHECK(strcmp(endpoint->host, opens == 0 ? "primary.test" : "replica.test") == 0);
    CHECK(endpoint->port == (opens == 0 ? 1234 : 5678));
    CHECK(strcmp(ca, "test-ca") == 0);
    int index = opens++;
    *out = NULL;
    if (outcomes[index].phase == 0 && outcomes[index].error) return outcomes[index].error;
    handles[index] = (struct client_connection){index, 0};
    *out = &handles[index]; live++;
    return CLIENT_TRANSPORT_OK;
}
void client_connection_close(client_connection_t *c) {
    if (c != NULL) { CHECK(live == 1); live--; }
}
int client_connection_write_all(client_connection_t *c, const void *buffer, size_t length) {
    CHECK(live == 1);
    struct outcome *o = &outcomes[c->index];
    if (o->phase == 1 && o->error) return o->error;
    if (buffer == current_password) {
        CHECK(length == 9 && memcmp(buffer, "qqqqqqqq", 9) == 0);
        password_writes++;
    }
    return CLIENT_TRANSPORT_OK;
}
int client_connection_read_exact(client_connection_t *c, void *buffer, size_t length) {
    CHECK(live == 1);
    struct outcome *o = &outcomes[c->index];
    if ((c->reads == 0 && o->phase == 2) || (c->reads > 0 && o->phase == 3)) {
        if (o->error) return o->error;
    }
    memset(buffer, 0, length);
    if (c->reads++ == 0) { CHECK(length == 1); *(unsigned char *)buffer = (unsigned char)o->status; }
    return CLIENT_TRANSPORT_OK;
}
const char *client_transport_result_string(int result) { (void)result; return "Injected transport result"; }

static void run(client_command_t command, struct outcome primary, struct outcome replica,
                int expected_opens, client_result_kind_t expected_kind, int expected_transport,
                int expected_status, const char *source, const char *destination) {
    outcomes[0] = primary; outcomes[1] = replica;
    opens = live = password_writes = 0;
    client_options_t options = {0};
    options.deployment.primary = (client_endpoint_t){"primary.test", 1234};
    options.deployment.replica = (client_endpoint_t){"replica.test", 5678};
    strcpy(options.deployment.ca_file, "test-ca");
    options.command = command; options.username = "alice"; options.remote_name = "file";
    options.local_path = command == CLIENT_COMMAND_UPLOAD ? source : destination;
    char password[100]; memset(password, 'z', sizeof(password)); memcpy(password, "qqqqqqqq", 9);
    current_password = password;
    FILE *output = tmpfile(); CHECK(output != NULL);
    client_command_result_t result = client_execute(&options, password, sizeof(password), output);
    CHECK(result.kind == expected_kind && result.transport == expected_transport && (int)result.status == expected_status);
    CHECK(opens == expected_opens && live == 0);
    for (size_t i = 0; i < sizeof(password); ++i) CHECK(password[i] == 0);
    if (expected_opens == 2 && primary.phase >= 2 && replica.phase >= 2) CHECK(password_writes == 2);
    CHECK(fclose(output) == 0);
    if (command == CLIENT_COMMAND_DOWNLOAD && expected_kind == CLIENT_RESULT_OK) CHECK(unlink(destination) == 0);
    else CHECK(access(destination, F_OK) != 0);
    ++cases;
}
int main(void) {
    char directory[] = "/tmp/cs469-routing-XXXXXX", source[128], destination[128];
    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(source, sizeof(source), "%s/source", directory) > 0);
    CHECK(snprintf(destination, sizeof(destination), "%s/destination", directory) > 0);
    FILE *file = fopen(source, "w"); CHECK(file != NULL && fclose(file) == 0);
    struct outcome success = {0, 2, 0};
    int eligible[] = {CLIENT_TRANSPORT_RESOLVE_ERROR, CLIENT_TRANSPORT_CONNECT_ERROR,
        CLIENT_TRANSPORT_TIMEOUT, CLIENT_TRANSPORT_IO_ERROR, CLIENT_TRANSPORT_EOF};
    int excluded[] = {CLIENT_TRANSPORT_INVALID_ARGUMENT, CLIENT_TRANSPORT_NO_MEMORY,
        CLIENT_TRANSPORT_TLS_CONTEXT_ERROR, CLIENT_TRANSPORT_TLS_CA_ERROR,
        CLIENT_TRANSPORT_TLS_VERIFY_ERROR, CLIENT_TRANSPORT_TLS_HANDSHAKE_ERROR, CLIENT_TRANSPORT_PROTOCOL_ERROR};
    for (int command = CLIENT_COMMAND_LIST; command <= CLIENT_COMMAND_DELETE; ++command) {
        int read_command = command == CLIENT_COMMAND_LIST || command == CLIENT_COMMAND_DOWNLOAD;
        for (size_t i = 0; i < sizeof(eligible)/sizeof(eligible[0]); ++i) {
            for (int phase = 0; phase < 3; ++phase) {
                struct outcome failure = {eligible[i], phase, 0};
                run((client_command_t)command, failure, success, read_command ? 2 : 1,
                    read_command ? CLIENT_RESULT_OK : CLIENT_RESULT_TRANSPORT,
                    read_command ? 0 : eligible[i], 0, source, destination);
                if (read_command) {
                    run((client_command_t)command, failure, failure, 2, CLIENT_RESULT_TRANSPORT, eligible[i], 0, source, destination);
                }
            }
            if (read_command) run((client_command_t)command, (struct outcome){eligible[i], 3, 0}, success,
                1, CLIENT_RESULT_TRANSPORT, eligible[i], 0, source, destination);
        }
        for (size_t i = 0; i < sizeof(excluded)/sizeof(excluded[0]); ++i) {
            run((client_command_t)command, (struct outcome){excluded[i], 0, 0}, success, 1,
                excluded[i] == CLIENT_TRANSPORT_PROTOCOL_ERROR ? CLIENT_RESULT_PROTOCOL : CLIENT_RESULT_TRANSPORT,
                excluded[i], 0, source, destination);
        }
        for (int status = 1; status <= 7; ++status)
            run((client_command_t)command, (struct outcome){0, 2, status}, success, 1, CLIENT_RESULT_STATUS, 0, status, source, destination);
        run((client_command_t)command, (struct outcome){0, 2, 255}, success, 1,
            CLIENT_RESULT_PROTOCOL, CLIENT_TRANSPORT_PROTOCOL_ERROR, 0, source, destination);
        run((client_command_t)command, success, success, 1, CLIENT_RESULT_OK, 0, 0, source, destination);
    }
    CHECK(unlink(source) == 0 && rmdir(directory) == 0);
    printf("PASS: %d deterministic routing/status-boundary cases, endpoint selection, attempt counts and password cleanup\n", cases);
    return 0;
}
