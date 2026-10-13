/* Direct DB fixtures plus a separately compiled fault-mapping mode. No server,
 * TLS, production credentials or shared authentication handles are involved. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "../server_auth.h"
#include "../password_db.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL auth line %d\n", __LINE__); exit(1); } } while (0)

#ifdef SERVER_AUTH_FAULT_TEST
struct password_db { int live; };
static struct password_db handle;
static int open_result, verify_result, opens, verifies, closes;
static const char *expected_password;
int password_db_open_existing(const char *path, password_db_t **out) {
    CHECK(path != NULL && handle.live == 0);
    ++opens; *out = NULL;
    if (open_result == PASSWORD_DB_OK) { handle.live = 1; *out = &handle; }
    return open_result;
}
int password_db_verify_user(password_db_t *db, const char *username, const char *password) {
    CHECK(db == &handle && db->live && strcmp(username, "alice") == 0 && password == expected_password);
    ++verifies; return verify_result;
}
void password_db_close(password_db_t *db) { CHECK(db == &handle && db->live); db->live = 0; ++closes; }
int main(void) {
    int results[] = {PASSWORD_DB_OK, PASSWORD_DB_USER_NOT_FOUND, PASSWORD_DB_PASSWORD_MISMATCH,
        PASSWORD_DB_INVALID_ARGUMENT, PASSWORD_DB_SQLITE_ERROR, PASSWORD_DB_CRYPTO_ERROR,
        PASSWORD_DB_NO_MEMORY, PASSWORD_DB_UNSUPPORTED_ALGORITHM, PASSWORD_DB_INVALID_RECORD,
        PASSWORD_DB_USER_EXISTS, PASSWORD_DB_STOPPED, -1, 999};
    for (size_t i = 0; i < sizeof(results)/sizeof(results[0]); ++i) {
        for (int fail_open = 0; fail_open < 2; ++fail_open) {
            opens = verifies = closes = 0;
            open_result = fail_open ? results[i] : PASSWORD_DB_OK;
            verify_result = results[i];
            char password[] = "secret"; expected_password = password;
            server_auth_result_t got = server_auth_verify("fixture", "alice", 6, password, sizeof(password));
            server_auth_result_t expected = SERVER_AUTH_INTERNAL;
            if (results[i] == PASSWORD_DB_OK) expected = SERVER_AUTH_OK;
            else if (!fail_open && (results[i] == PASSWORD_DB_USER_NOT_FOUND || results[i] == PASSWORD_DB_PASSWORD_MISMATCH))
                expected = SERVER_AUTH_FAILED;
            CHECK(got == expected && opens == 1 && handle.live == 0);
            CHECK(verifies == (open_result == PASSWORD_DB_OK) && closes == verifies);
            for (size_t j = 0; j < sizeof(password); ++j) CHECK(password[j] == 0);
        }
    }
    CHECK(server_auth_to_error((server_auth_result_t)-1) == ERR_INTERNAL);
    CHECK(server_auth_to_error((server_auth_result_t)999) == ERR_INTERNAL);
    puts("PASS: 26 injected DB open/verify result mappings, ownership and password erasure");
    return 0;
}
#else
#include <openssl/evp.h>
#include <sqlite3.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

static const char secret[] = "AUTH_TEST_SECRET_KeepPrivate42!";
static int checks;
static void verify(const char *path, const char *user, size_t user_size,
                   const char *bytes, size_t size, server_auth_result_t expected) {
    char password[128]; CHECK(size <= sizeof(password));
    memset(password, 'z', sizeof(password));
    if (bytes != NULL) memcpy(password, bytes, size);
    server_auth_result_t got = server_auth_verify(path, user, user_size, bytes ? password : NULL, size);
    CHECK(got == expected);
    if (bytes) {
        for (size_t i = 0; i < size; ++i) CHECK(password[i] == 0);
        for (size_t i = size; i < sizeof(password); ++i) CHECK(password[i] == 'z');
    }
    OPENSSL_cleanse(password, sizeof(password));
    ++checks;
}
static void sql(sqlite3 *db, const char *query) { CHECK(sqlite3_exec(db, query, NULL, NULL, NULL) == SQLITE_OK); }
static void digest(const char *path, unsigned char out[32]) {
    FILE *file = fopen(path, "rb"); CHECK(file != NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); CHECK(ctx != NULL);
    CHECK(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    unsigned char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) != 0) CHECK(EVP_DigestUpdate(ctx, buf, n) == 1);
    CHECK(!ferror(file) && fclose(file) == 0);
    unsigned int length; CHECK(EVP_DigestFinal_ex(ctx, out, &length) == 1 && length == 32);
    EVP_MD_CTX_free(ctx);
}
struct thread_input { const char *path; int ok; };
static void *worker(void *arg) {
    struct thread_input *input = arg;
    input->ok = 1;
    for (int i = 0; i < 2; ++i) {
        char password[sizeof(secret)]; memcpy(password, secret, sizeof(password));
        if (server_auth_verify(input->path, "alice", 6, password, sizeof(password)) != SERVER_AUTH_OK) input->ok = 0;
        for (size_t j = 0; j < sizeof(password); ++j) if (password[j] != 0) input->ok = 0;
    }
    return NULL;
}
int main(void) {
    char directory[] = "/tmp/cs469-auth-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char dbpath[256], missing[256], empty[256], junk[256], fifo[256];
    CHECK(snprintf(dbpath, sizeof(dbpath), "%s/users.db", directory) > 0);
    CHECK(snprintf(missing, sizeof(missing), "%s/missing.db", directory) > 0);
    CHECK(snprintf(empty, sizeof(empty), "%s/empty.db", directory) > 0);
    CHECK(snprintf(junk, sizeof(junk), "%s/junk.db", directory) > 0);
    CHECK(snprintf(fifo, sizeof(fifo), "%s/fifo", directory) > 0);
    /* Capture all underlying diagnostics and prove plaintext is absent. */
    FILE *capture = tmpfile(); CHECK(capture != NULL);
    int original_error = dup(STDERR_FILENO); CHECK(original_error >= 0);
    CHECK(fflush(stderr) == 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
    password_db_t *db = NULL;
    CHECK(password_db_open(dbpath, &db) == PASSWORD_DB_OK);
    CHECK(password_db_init_schema(db) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(db, "alice", secret) == PASSWORD_DB_OK);
    char max_user[65], max_password[65], oversized[66];
    memset(max_user, 'u', 64); max_user[64] = 0;
    memset(max_password, '~', 64); max_password[64] = 0;
    memset(oversized, 'x', 65); oversized[65] = 0;
    CHECK(password_db_add_user(db, max_user, max_password) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(db, "corrupt", secret) == PASSWORD_DB_OK);
    password_db_close(db); db = NULL;
    unsigned char before[32], after[32]; digest(dbpath, before);
    verify(dbpath, "alice", 6, secret, sizeof(secret), SERVER_AUTH_OK);
    verify(dbpath, "alice", 6, "wrong", 6, SERVER_AUTH_FAILED);
    verify(dbpath, "unknown", 8, secret, sizeof(secret), SERVER_AUTH_FAILED);
    CHECK(server_auth_to_error(SERVER_AUTH_OK) == ERR_OK);
    CHECK(server_auth_to_error(SERVER_AUTH_FAILED) == ERR_AUTH_FAILED);
    CHECK(server_auth_to_error(SERVER_AUTH_BAD_REQUEST) == ERR_BAD_REQUEST);
    CHECK(server_auth_to_error(SERVER_AUTH_INTERNAL) == ERR_INTERNAL);
    const char *bad_names[] = {"", ".", "..", "a/b", "a\\b", "a.b", "a b", "a\n", "a\177", "a\200", oversized};
    for (size_t i = 0; i < sizeof(bad_names)/sizeof(bad_names[0]); ++i)
        verify(dbpath, bad_names[i], strlen(bad_names[i]) + 1, secret, sizeof(secret), SERVER_AUTH_BAD_REQUEST);
    const char *bad_passwords[] = {"", "a\n", "a\t", "a\177", "a\200", oversized};
    for (size_t i = 0; i < sizeof(bad_passwords)/sizeof(bad_passwords[0]); ++i)
        verify(dbpath, "alice", 6, bad_passwords[i], strlen(bad_passwords[i]) + 1, SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, max_user, sizeof(max_user), max_password, sizeof(max_password), SERVER_AUTH_OK);
    verify(dbpath, "alice", 6, "a b!", 5, SERVER_AUTH_FAILED); /* printable space is valid */
    char unterminated[65]; memset(unterminated, 'q', sizeof(unterminated));
    verify(dbpath, unterminated, sizeof(unterminated), secret, sizeof(secret), SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, "alice", 6, unterminated, sizeof(unterminated), SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, "ali\0ce", 7, secret, sizeof(secret), SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, "alice", 6, "a\0b", 4, SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, NULL, 0, secret, sizeof(secret), SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, "alice", 6, NULL, 0, SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, "alice", 0, secret, sizeof(secret), SERVER_AUTH_BAD_REQUEST);
    verify(dbpath, "alice", 6, secret, 0, SERVER_AUTH_BAD_REQUEST);
    verify(NULL, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    verify("", "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    verify(":memory:", "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    verify("file:memory?mode=memory", "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    verify(missing, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    CHECK(access(missing, F_OK) != 0 && errno == ENOENT);
    verify(directory, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    CHECK(mkfifo(fifo, 0600) == 0);
    verify(fifo, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    CHECK(unlink(fifo) == 0);
    CHECK(chmod(dbpath, 0000) == 0);
    if (geteuid() != 0) verify(dbpath, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    CHECK(chmod(dbpath, 0600) == 0);
    CHECK(password_db_open_existing(dbpath, NULL) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_open_existing(NULL, &db) == PASSWORD_DB_INVALID_ARGUMENT && db == NULL);
    CHECK(password_db_open_existing(missing, &db) == PASSWORD_DB_SQLITE_ERROR && db == NULL);
    CHECK(password_db_open_existing(dbpath, &db) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(db, "alice", secret) == PASSWORD_DB_OK);
    CHECK(password_db_delete_user(db, "alice") == PASSWORD_DB_SQLITE_ERROR);
    password_db_close(db); db = NULL;
    digest(dbpath, after); CHECK(memcmp(before, after, 32) == 0);
    for (int i = 0; i < 3; ++i) verify(dbpath, "alice", 6, secret, sizeof(secret), SERVER_AUTH_OK);
    pthread_t threads[4]; struct thread_input inputs[4];
    for (int i = 0; i < 4; ++i) { inputs[i] = (struct thread_input){dbpath, 0}; CHECK(pthread_create(&threads[i], NULL, worker, &inputs[i]) == 0); }
    for (int i = 0; i < 4; ++i) { CHECK(pthread_join(threads[i], NULL) == 0 && inputs[i].ok); }
    digest(dbpath, after); CHECK(memcmp(before, after, 32) == 0);
    /* Provision empty file through the existing API, but deliberately no schema. */
    CHECK(password_db_open(empty, &db) == PASSWORD_DB_OK); password_db_close(db); db = NULL;
    verify(empty, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    CHECK(password_db_open_existing(empty, &db) == PASSWORD_DB_OK);
    CHECK(password_db_init_schema(db) == PASSWORD_DB_SQLITE_ERROR);
    password_db_close(db); db = NULL;
    struct stat st; CHECK(stat(empty, &st) == 0 && st.st_size == 0);
    FILE *file = fopen(junk, "w"); CHECK(file != NULL && fputs("not a SQLite database", file) >= 0 && fclose(file) == 0);
    verify(junk, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    sqlite3 *inspection = NULL; CHECK(sqlite3_open(dbpath, &inspection) == SQLITE_OK);
    sql(inspection, "UPDATE users SET algorithm='not-supported' WHERE username='corrupt'");
    verify(dbpath, "corrupt", 8, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    sql(inspection, "UPDATE users SET algorithm='PBKDF2-HMAC-SHA256',salt=x'00' WHERE username='corrupt'");
    verify(dbpath, "corrupt", 8, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    sql(inspection, "UPDATE users SET salt=zeroblob(16),iterations=0 WHERE username='corrupt'");
    verify(dbpath, "corrupt", 8, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    sql(inspection, "BEGIN EXCLUSIVE");
    verify(dbpath, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL); /* actual lock timeout */
    sql(inspection, "ROLLBACK");
    verify(dbpath, "alice", 6, secret, sizeof(secret), SERVER_AUTH_OK);
    CHECK(sqlite3_close(inspection) == SQLITE_OK);
    CHECK(sqlite3_open(empty, &inspection) == SQLITE_OK);
    sql(inspection, "CREATE TABLE users(unrelated INTEGER)");
    CHECK(sqlite3_close(inspection) == SQLITE_OK);
    verify(empty, "alice", 6, secret, sizeof(secret), SERVER_AUTH_INTERNAL);
    CHECK(unlink(dbpath) == 0 && unlink(empty) == 0 && unlink(junk) == 0 && rmdir(directory) == 0);
    CHECK(fflush(stderr) == 0 && dup2(original_error, STDERR_FILENO) >= 0 && close(original_error) == 0);
    rewind(capture); char logs[8192]; size_t log_size = fread(logs, 1, sizeof(logs) - 1, capture); logs[log_size] = 0;
    CHECK(!ferror(capture) && feof(capture) && strstr(logs, secret) == NULL && strstr(logs, "alice") == NULL);
    CHECK(fclose(capture) == 0);
    printf("PASS: %d authentication cases, 8 concurrent verifications, read-only ownership, DB integrity, cleanup and secret-free diagnostics\n", checks);
    return 0;
}
#endif
