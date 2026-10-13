#include "../server_protocol_fields.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "fields failure line %d\n", __LINE__); exit(1); } } while (0)
struct memory { const char *bytes; size_t count, offset; uint8_t status; size_t written; };
static int get(void *state, void *out, size_t n) {
    struct memory *m = state;
    if (n > m->count - m->offset) return -1;
    memcpy(out, m->bytes + m->offset, n); m->offset += n; return 0;
}
static int put(void *state, const void *bytes, size_t n) {
    struct memory *m = state; CHECK(n == 1);
    m->status = *(const uint8_t *)bytes; m->written += n; return 0;
}
int main(void) {
    struct memory m = {0};
    server_read_io_t io = {&m, get, put, NULL};
    error_code_t statuses[] = {ERR_OK, ERR_AUTH_FAILED, ERR_NOT_FOUND, ERR_EXISTS,
        ERR_BAD_REQUEST, ERR_TOO_LARGE, ERR_REPLICATION_FAILED, ERR_INTERNAL};
    for (size_t i = 0; i < 8; ++i) {
        CHECK(server_write_status(&io, statuses[i]) == 0 && m.status == i && m.written == i + 1);
    }
    CHECK(server_status_byte((error_code_t)999) == 7);
    char out[65], bytes[67]; memset(bytes, 'x', sizeof(bytes)); bytes[64] = 0;
    m.bytes = bytes; m.count = sizeof(bytes);
    CHECK(server_read_field(&io, out, sizeof(out)) == 65 && m.offset == 65);
    bytes[64] = 'x'; m.offset = 0;
    CHECK(server_read_field(&io, out, sizeof(out)) == 0 && m.offset == 65);
    for (size_t n = 0; n < 65; ++n) {
        m.count = n; m.offset = 0;
        CHECK(server_read_field(&io, out, sizeof(out)) == 0 && m.offset == n);
    }
    puts("PASS: all 8 explicit single-byte statuses, unknown status, bounded field/EOF boundaries");
}
