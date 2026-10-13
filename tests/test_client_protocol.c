/* In-memory transport double: exact wire assertions independent of TLS/server. */
#include "../client_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL protocol line %d\n", __LINE__); exit(1); } } while (0)
struct client_connection { unsigned char bytes[4096]; size_t size, offset; };
int client_connection_write_all(client_connection_t *c, const void *b, size_t n) {
    if (c == NULL || n > sizeof(c->bytes) - c->size) return CLIENT_TRANSPORT_IO_ERROR;
    memcpy(c->bytes + c->size, b, n); c->size += n; return CLIENT_TRANSPORT_OK;
}
int client_connection_read_exact(client_connection_t *c, void *b, size_t n) {
    if (c == NULL || n > c->size - c->offset) return CLIENT_TRANSPORT_EOF;
    memcpy(b, c->bytes + c->offset, n); c->offset += n; return CLIENT_TRANSPORT_OK;
}
int main(void) {
    client_status_t status = CLIENT_STATUS_INTERNAL;
    for (int i = 0; i < 256; ++i) {
        int rc = client_status_decode((uint8_t)i, &status);
        CHECK(rc == (i <= 7 ? CLIENT_TRANSPORT_OK : CLIENT_TRANSPORT_PROTOCOL_ERROR));
        CHECK((int)status == (i <= 7 ? i : 7));
    }
    CHECK(client_status_decode(0, NULL) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    const char *expected[] = {"LISTu\0p\0", ("UPLOADu\0p\0\x12\x34\x56\x78" "f\0"), "DOWNLOADu\0p\0f\0", "DELETEu\0p\0f\0"};
    const size_t lengths[] = {8, 16, 14, 12};
    for (int i = 0; i < 4; ++i) {
        client_connection_t c = {0};
        CHECK(client_protocol_write_request(&c, (client_command_t)i, "u", "p", "f", 0x12345678) == 0);
        CHECK(c.size == lengths[i] && memcmp(c.bytes, expected[i], lengths[i]) == 0);
    }
    client_connection_t c = {0};
    for (int field = 0; field < 2; ++field) {
        size_t limit = field == 0 ? 64 : 256;
        char value[258]; memset(value, 'a', sizeof(value)); value[limit] = 0;
        CHECK(client_protocol_write_string(&c, value, (client_field_t)field) == 0);
        value[limit] = 'a'; value[limit + 1] = 0;
        CHECK(client_protocol_validate(value, (client_field_t)field) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    }
    char credential[66]; memset(credential, 'q', 64); credential[64] = 0;
    c.size = 0;
    CHECK(client_protocol_write_request(&c, CLIENT_COMMAND_LIST, credential, credential, NULL, 0) == 0);
    credential[64] = 'q'; credential[65] = 0; c.size = 0;
    CHECK(client_protocol_write_request(&c, CLIENT_COMMAND_LIST, "u", credential, NULL, 0) == CLIENT_TRANSPORT_INVALID_ARGUMENT && c.size == 0);
    CHECK(client_protocol_write_request(&c, CLIENT_COMMAND_LIST, credential, "p", NULL, 0) == CLIENT_TRANSPORT_INVALID_ARGUMENT && c.size == 0);
    const char *bad[] = {"", ".", "..", "a/b", "a\\b", "a\n", "a\177", "a\200"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        CHECK(client_protocol_validate(bad[i], CLIENT_FIELD_FILENAME) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    CHECK(client_protocol_validate("a\n", CLIENT_FIELD_CREDENTIAL) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    CHECK(client_protocol_validate("a\200", CLIENT_FIELD_CREDENTIAL) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    c = (client_connection_t){0}; uint32_t value = 0;
    CHECK(client_protocol_write_u32(&c, UINT32_MAX) == 0);
    CHECK(client_protocol_read_u32(&c, &value) == 0 && value == UINT32_MAX);
    CHECK(client_protocol_read_u32(&c, &value) == CLIENT_TRANSPORT_EOF);
    char filename[257];
    c = (client_connection_t){0};
    memset(c.bytes, 'a', 256); c.bytes[256] = 0; c.size = 257;
    CHECK(client_protocol_read_filename(&c, filename) == 0 && strlen(filename) == 256);
    c.offset = 0; c.bytes[256] = 'a';
    CHECK(client_protocol_read_filename(&c, filename) == CLIENT_TRANSPORT_PROTOCOL_ERROR);
    c = (client_connection_t){0}; c.bytes[0] = 255; c.size = 1;
    CHECK(client_protocol_read_status(&c, &status) == CLIENT_TRANSPORT_PROTOCOL_ERROR);
    puts("All protocol tests passed (status, exact requests, limits, ASCII, u32 and bounded decoding).");
    return 0;
}
