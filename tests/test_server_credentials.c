#define _DARWIN_C_SOURCE
#include "../server.h"
#include "../server_protocol_io.h"
#include "../password_db.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "credentials failure line %d\n", __LINE__); exit(1); } } while (0)
/* Only server_ops' dedicated test object substitutes adapter initialization and
 * cleanse. Authentication and the read-only DB implementation are real. */
static const char *input;
static size_t length, offset;
static int cleanses, fail_init;
static int get(void *state, void *out, size_t n) {
    (void)state;
    if (n > length - offset) return -1;
    memcpy(out, input + offset, n); offset += n; return 0;
}
int server_credentials_test_io_init(server_protocol_io_t *state, SSL *ssl, int timeout,
                                    server_read_io_t *io) {
    (void)state; (void)ssl; CHECK(timeout == 3000);
    if (fail_init) return -1;
    *io = (server_read_io_t){NULL, get, NULL, NULL}; return 0;
}
void server_credentials_test_cleanse(void *bytes, size_t n) {
    CHECK(n == 65); OPENSSL_cleanse(bytes, n);
    for (size_t i = 0; i < n; ++i) CHECK(((unsigned char *)bytes)[i] == 0);
    ++cleanses;
}
static int cases;
static void run(server_config_t *config, const char *bytes, size_t n, error_code_t expected) {
    input = bytes; length = n; offset = 0;
    char user[65]; int before = cleanses;
    CHECK(read_and_verify_credentials(NULL, config, user) == expected);
    CHECK(cleanses == before + 1); ++cases;
}
int main(void) {
    char root[] = "/tmp/cs469-production-auth-XXXXXX"; CHECK(mkdtemp(root));
    char path[256]; snprintf(path, sizeof(path), "%s/users.db", root);
    password_db_t *db = NULL; CHECK(password_db_open(path, &db) == PASSWORD_DB_OK);
    CHECK(password_db_init_schema(db) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(db, "alice", "secret") == PASSWORD_DB_OK);
    password_db_close(db);
    server_config_t config = {.auth_db_path=path, .timeout_sec=3};
    const char valid[] = "alice\0secret";
    run(&config, valid, sizeof(valid), ERR_OK);
    for (size_t i = 0; i < sizeof(valid); ++i) run(&config, valid, i, ERR_BAD_REQUEST);
    const char wrong[] = "alice\0wrong", unknown[] = "unknown\0secret", invalid[] = "../alice\0secret";
    run(&config, wrong, sizeof(wrong), ERR_AUTH_FAILED);
    run(&config, unknown, sizeof(unknown), ERR_AUTH_FAILED);
    run(&config, invalid, sizeof(invalid), ERR_BAD_REQUEST);
    char oversized[72]; memcpy(oversized, "alice", 6); memset(oversized + 6, 'p', 66);
    run(&config, oversized, sizeof(oversized), ERR_BAD_REQUEST);
    fail_init = 1; run(&config, valid, sizeof(valid), ERR_INTERNAL); fail_init = 0;
    config.auth_db_path = "/nonexistent-cs469-production-db";
    run(&config, valid, sizeof(valid), ERR_INTERNAL);
    CHECK(unlink(path) == 0 && rmdir(root) == 0);
    printf("PASS: %d production write-credential cases, full buffer erasure on every path\n", cases);
}
