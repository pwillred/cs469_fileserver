/*
 * CS 469
 * Isolated lifecycle, schema and password tests. Direct SQLite access inspects
 * stored parameters and creates deliberately malformed or alternative records.
 */
#define _POSIX_C_SOURCE 200809L
/* macOS exposes mkdtemp through its Darwin extensions. */
#define _DARWIN_C_SOURCE
#include "../password_db.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        goto cleanup; \
    } \
} while (0)

/* Returns one integer from a read-only query, checking statement cleanup too. */
static int query_int(sqlite3 *db, const char *sql, int *value) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            *value = sqlite3_column_int(stmt, 0);
            rc = sqlite3_step(stmt) == SQLITE_DONE ? SQLITE_OK : SQLITE_ERROR;
        } else {
            rc = SQLITE_ERROR;
        }
    }
    int close_rc = sqlite3_finalize(stmt);
    return rc == SQLITE_OK ? close_rc : rc;
}

static int test_passwords(const char *path, sqlite3 *inspection) {
    password_db_t *first = NULL;
    password_db_t *second = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = EXIT_FAILURE;
    int count = 0;
    unsigned char fixture_salt[16] = {0};
    unsigned char fixture_hash[32] = {0};
    const char *password = "0123456789abcdef0123456789abcdef";
    char longest_username[65];
    char long_username[66];
    char longest_password[4097];
    char long_password[4098];
    memset(longest_username, 'a', sizeof(longest_username) - 1);
    longest_username[sizeof(longest_username) - 1] = '\0';
    memset(long_username, 'a', sizeof(long_username) - 1);
    long_username[sizeof(long_username) - 1] = '\0';
    memset(longest_password, 'p', sizeof(longest_password) - 1);
    longest_password[sizeof(longest_password) - 1] = '\0';
    memset(long_password, 'p', sizeof(long_password) - 1);
    long_password[sizeof(long_password) - 1] = '\0';

    CHECK(password_db_open(path, &first) == PASSWORD_DB_OK);
    CHECK(password_db_open(path, &second) == PASSWORD_DB_OK);
    int (*operations[])(password_db_t *, const char *, const char *) = {
        password_db_add_user, password_db_verify_user
    };
    const char *invalid_names[] = {
        "", ".", "..", "../user", "a/b", "a\\b", "a.b", "a b", "a\nb",
        "user'--", "user;DROP TABLE users", "a:b", "%2e%2e", "\xff", long_username
    };
    for (size_t op = 0; op < sizeof(operations) / sizeof(operations[0]); ++op) {
        CHECK(operations[op](NULL, "alice", password) == PASSWORD_DB_INVALID_ARGUMENT);
        CHECK(operations[op](first, NULL, password) == PASSWORD_DB_INVALID_ARGUMENT);
        CHECK(operations[op](first, "alice", NULL) == PASSWORD_DB_INVALID_ARGUMENT);
        CHECK(operations[op](first, "alice", "") == PASSWORD_DB_INVALID_ARGUMENT);
        CHECK(operations[op](first, "alice", long_password) == PASSWORD_DB_INVALID_ARGUMENT);
        for (size_t i = 0; i < sizeof(invalid_names) / sizeof(invalid_names[0]); ++i) {
            CHECK(operations[op](first, invalid_names[i], password) == PASSWORD_DB_INVALID_ARGUMENT);
        }
    }
    puts("PASS: add/verify null inputs, empty passwords, lengths and unsafe usernames");

    CHECK(password_db_add_user(first, "alice", password) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(second, "alice", "different") == PASSWORD_DB_USER_EXISTS);
    CHECK(password_db_verify_user(first, "alice", password) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "alice", "wrong") == PASSWORD_DB_PASSWORD_MISMATCH);
    CHECK(password_db_verify_user(first, "missing", password) == PASSWORD_DB_USER_NOT_FOUND);
    CHECK(password_db_verify_user(first, "Alice", password) == PASSWORD_DB_USER_NOT_FOUND);
    CHECK(password_db_add_user(second, "bob", password) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "bob", password) == PASSWORD_DB_OK);
    puts("PASS: insertion, duplicate without replacement, match, mismatch and unknown user");

    CHECK(query_int(inspection,
        "SELECT count(*) FROM users WHERE username IN ('alice','bob') "
        "AND typeof(salt)='blob' AND length(salt)=16 "
        "AND typeof(password_hash)='blob' AND length(password_hash)=32 "
        "AND password_hash<>CAST('0123456789abcdef0123456789abcdef' AS BLOB) "
        "AND algorithm='PBKDF2-HMAC-SHA256' AND iterations=600000", &count) == SQLITE_OK);
    CHECK(count == 2);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM users a, users b WHERE a.username='alice' AND b.username='bob' "
        "AND a.salt<>b.salt AND a.password_hash<>b.password_hash", &count) == SQLITE_OK);
    CHECK(count == 1);
    puts("PASS: random salts, distinct hashes, no plaintext hash, stored KDF parameters");

    CHECK(password_db_add_user(first, longest_username, longest_password) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, longest_username, longest_password) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(first, "User_0-test", " \xff\x80\n'\\") == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "User_0-test", " \xff\x80\n'\\") == PASSWORD_DB_OK);
    puts("PASS: maximum input lengths and non-ASCII/control bytes in passwords");

    password_db_close(first);
    first = NULL;
    CHECK(password_db_open(path, &first) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(first, "alice", password) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "alice", password) == PASSWORD_DB_OK);
    password_db_close(second);
    second = NULL;
    CHECK(password_db_verify_user(first, "alice", password) == PASSWORD_DB_OK);
    puts("PASS: persisted verification and independent connection lifetimes");

    /* Construct a record independently at a non-default cost. Verification
     * must derive from the stored value rather than the new-user default.
     */
    memset(fixture_salt, 7, sizeof(fixture_salt));
    CHECK(PKCS5_PBKDF2_HMAC(password, (int)strlen(password), fixture_salt,
        sizeof(fixture_salt), 12345, EVP_sha256(), sizeof(fixture_hash), fixture_hash) == 1);
    CHECK(sqlite3_prepare_v2(inspection,
        "INSERT INTO users(username,salt,password_hash,algorithm,iterations) "
        "VALUES('fixture',?1,?2,'PBKDF2-HMAC-SHA256',12345)", -1, &stmt, NULL) == SQLITE_OK);
    CHECK(sqlite3_bind_blob(stmt, 1, fixture_salt, sizeof(fixture_salt), SQLITE_STATIC) == SQLITE_OK);
    CHECK(sqlite3_bind_blob(stmt, 2, fixture_hash, sizeof(fixture_hash), SQLITE_STATIC) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_DONE);
    int rc = sqlite3_finalize(stmt);
    stmt = NULL;
    CHECK(rc == SQLITE_OK);
    CHECK(password_db_verify_user(first, "fixture", password) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(first, "fixture", "wrong") == PASSWORD_DB_PASSWORD_MISMATCH);
    CHECK(sqlite3_exec(inspection, "UPDATE users SET iterations=12346 WHERE username='fixture'",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_verify_user(first, "fixture", password) == PASSWORD_DB_PASSWORD_MISMATCH);
    CHECK(sqlite3_exec(inspection, "UPDATE users SET iterations=12345,algorithm='unsupported' WHERE username='fixture'",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_verify_user(first, "fixture", password) == PASSWORD_DB_UNSUPPORTED_ALGORITHM);
    CHECK(sqlite3_exec(inspection, "UPDATE users SET algorithm='PBKDF2-HMAC-SHA256' WHERE username='fixture'",
        NULL, NULL, NULL) == SQLITE_OK);
    puts("PASS: stored iteration count and unsupported algorithm handling");

    const char *malformed_updates[] = {
        "UPDATE users SET iterations=0 WHERE username='fixture'",
        "UPDATE users SET iterations=-1 WHERE username='fixture'",
        "UPDATE users SET iterations=10000001 WHERE username='fixture'",
        "UPDATE users SET iterations=4294967297 WHERE username='fixture'",
        "UPDATE users SET iterations=1.5 WHERE username='fixture'",
        "UPDATE users SET iterations='bad' WHERE username='fixture'",
        "UPDATE users SET iterations=12345,salt=X'' WHERE username='fixture'",
        "UPDATE users SET salt=zeroblob(16),password_hash=zeroblob(31) WHERE username='fixture'",
        "UPDATE users SET salt='0123456789abcdef',password_hash=zeroblob(32) WHERE username='fixture'"
    };
    for (size_t i = 0; i < sizeof(malformed_updates) / sizeof(malformed_updates[0]); ++i) {
        CHECK(sqlite3_exec(inspection, malformed_updates[i], NULL, NULL, NULL) == SQLITE_OK);
        CHECK(password_db_verify_user(first, "fixture", password) == PASSWORD_DB_INVALID_RECORD);
    }
    CHECK(password_db_verify_user(first, "alice", password) == PASSWORD_DB_OK);
    CHECK(sqlite3_exec(inspection, "DROP TABLE users", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_verify_user(first, "alice", password) == PASSWORD_DB_SQLITE_ERROR);
    CHECK(password_db_add_user(first, "alice", password) == PASSWORD_DB_SQLITE_ERROR);
    CHECK(password_db_init_schema(first) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(first, "recovered", password) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(first, "recovered", password) == PASSWORD_DB_OK);
    puts("PASS: malformed records, database errors and recovery");
    result = EXIT_SUCCESS;

cleanup:
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        result = EXIT_FAILURE;
    }
    OPENSSL_cleanse(fixture_hash, sizeof(fixture_hash));
    OPENSSL_cleanse(fixture_salt, sizeof(fixture_salt));
    OPENSSL_cleanse(longest_password, sizeof(longest_password));
    OPENSSL_cleanse(long_password, sizeof(long_password));
    password_db_close(first);
    password_db_close(second);
    return result;
}


/* Copy borrowed callback names so their contents can be checked after return. */
struct user_list {
    char names[8][65];
    size_t count;
    int stop;
};

static int collect_user(const char *username, void *context) {
    struct user_list *list = context;
    if (list->count >= 8 || strlen(username) >= sizeof(list->names[0])) {
        return -1;
    }
    strcpy(list->names[list->count++], username);
    return list->stop;
}

static int stop_without_context(const char *username, void *context) {
    return username != NULL && context == NULL ? 1 : 0;
}

static int test_management(const char *path, sqlite3 *inspection) {
    password_db_t *first = NULL;
    password_db_t *second = NULL;
    sqlite3_stmt *stmt = NULL;
    unsigned char salt[16] = {7};
    unsigned char hash[32] = {0};
    struct user_list list = {0};
    int count = 0;
    int result = EXIT_FAILURE;
    char too_long[4098];
    memset(too_long, 'p', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    CHECK(password_db_open(path, &first) == PASSWORD_DB_OK);
    CHECK(password_db_open(path, &second) == PASSWORD_DB_OK);
    CHECK(sqlite3_exec(inspection, "DELETE FROM users", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_list_users(first, collect_user, &list) == PASSWORD_DB_OK);
    CHECK(list.count == 0);
    CHECK(password_db_list_users(NULL, collect_user, &list) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_list_users(first, NULL, NULL) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_list_users(first, stop_without_context, NULL) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(first, "bob", "original") == PASSWORD_DB_OK);
    CHECK(password_db_list_users(second, collect_user, &list) == PASSWORD_DB_OK);
    CHECK(list.count == 1 && strcmp(list.names[0], "bob") == 0);
    CHECK(password_db_add_user(second, "zoe", "other") == PASSWORD_DB_OK);
    CHECK(password_db_add_user(first, "Alice", "other") == PASSWORD_DB_OK);
    list = (struct user_list){0};
    CHECK(password_db_list_users(second, collect_user, &list) == PASSWORD_DB_OK);
    CHECK(list.count == 3 && strcmp(list.names[0], "Alice") == 0 &&
        strcmp(list.names[1], "bob") == 0 && strcmp(list.names[2], "zoe") == 0);
    list = (struct user_list){.stop = -7};
    CHECK(password_db_list_users(first, collect_user, &list) == PASSWORD_DB_STOPPED);
    CHECK(list.count == 1 && strcmp(list.names[0], "Alice") == 0);
    CHECK(password_db_list_users(first, stop_without_context, NULL) == PASSWORD_DB_STOPPED);
    /* A second connection can write after early termination: no read lock leaks. */
    CHECK(password_db_add_user(second, "temporary", "other") == PASSWORD_DB_OK);
    CHECK(password_db_delete_user(second, "temporary") == PASSWORD_DB_OK);
    puts("PASS: empty/single/ordered username-only lists, callbacks and early-stop cleanup");

    const char *invalid[] = {"", ".", "..", "a/b", "a\\b", "a b", "x'--", too_long};
    CHECK(password_db_change_password(NULL, "bob", "new") == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_change_password(first, NULL, "new") == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_change_password(first, "bob", NULL) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_change_password(first, "bob", "") == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_change_password(first, "bob", too_long) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_delete_user(NULL, "bob") == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_delete_user(first, NULL) == PASSWORD_DB_INVALID_ARGUMENT);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(password_db_change_password(first, invalid[i], "new") == PASSWORD_DB_INVALID_ARGUMENT);
        CHECK(password_db_delete_user(first, invalid[i]) == PASSWORD_DB_INVALID_ARGUMENT);
    }
    CHECK(password_db_change_password(first, "missing", "new") == PASSWORD_DB_USER_NOT_FOUND);
    CHECK(password_db_verify_user(first, "bob", "original") == PASSWORD_DB_OK);
    puts("PASS: management input validation, unknown user and rejected-change preservation");

    /* Supply a valid legacy-cost credential and deterministic timestamp values.
     * Password change must upgrade cost, retain identity and refresh only updated_at.
     */
    CHECK(PKCS5_PBKDF2_HMAC("original", 8, salt, sizeof(salt), 12345,
        EVP_sha256(), sizeof(hash), hash) == 1);
    CHECK(sqlite3_prepare_v2(inspection,
        "UPDATE users SET salt=?1,password_hash=?2,iterations=12345,"
        "created_at='2000-01-01 00:00:00',updated_at='2001-01-01 00:00:00' WHERE username='bob'",
        -1, &stmt, NULL) == SQLITE_OK);
    CHECK(sqlite3_bind_blob(stmt, 1, salt, sizeof(salt), SQLITE_STATIC) == SQLITE_OK);
    CHECK(sqlite3_bind_blob(stmt, 2, hash, sizeof(hash), SQLITE_STATIC) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_DONE);
    int rc = sqlite3_finalize(stmt);
    stmt = NULL;
    CHECK(rc == SQLITE_OK);
    CHECK(password_db_verify_user(second, "bob", "original") == PASSWORD_DB_OK);
    CHECK(sqlite3_exec(inspection, "CREATE TEMP TABLE before_change AS SELECT * FROM users WHERE username='bob'",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_change_password(first, "bob", "replacement") == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "bob", "original") == PASSWORD_DB_PASSWORD_MISMATCH);
    CHECK(password_db_verify_user(second, "bob", "replacement") == PASSWORD_DB_OK);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM users u JOIN before_change b ON u.id=b.id WHERE u.username=b.username "
        "AND u.created_at=b.created_at AND u.salt<>b.salt AND u.password_hash<>b.password_hash "
        "AND length(u.salt)=16 AND length(u.password_hash)=32 "
        "AND u.algorithm='PBKDF2-HMAC-SHA256' AND u.iterations=600000 "
        "AND u.updated_at<>b.updated_at AND datetime(u.updated_at) IS NOT NULL "
        "AND u.updated_at>='2001-01-01 00:00:00' AND u.updated_at<=CURRENT_TIMESTAMP",
        &count) == SQLITE_OK);
    CHECK(count == 1);
    puts("PASS: password replacement, fresh salt/hash, default KDF, identity and timestamps");

    CHECK(sqlite3_exec(inspection,
        "DELETE FROM before_change; INSERT INTO before_change SELECT * FROM users WHERE username='bob';"
        "CREATE TRIGGER reject_change BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT,'forced'); END;",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_change_password(first, "bob", "rejected") == PASSWORD_DB_SQLITE_ERROR);
    CHECK(password_db_verify_user(second, "bob", "replacement") == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "bob", "rejected") == PASSWORD_DB_PASSWORD_MISMATCH);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM (SELECT * FROM users WHERE username='bob' INTERSECT SELECT * FROM before_change)",
        &count) == SQLITE_OK);
    CHECK(count == 1);
    CHECK(sqlite3_exec(inspection, "DROP TRIGGER reject_change; DROP TABLE before_change;"
        "CREATE TRIGGER reject_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'forced'); END;",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_delete_user(first, "zoe") == PASSWORD_DB_SQLITE_ERROR);
    CHECK(password_db_verify_user(second, "zoe", "other") == PASSWORD_DB_OK);
    CHECK(sqlite3_exec(inspection, "DROP TRIGGER reject_delete", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_delete_user(first, "zoe") == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "zoe", "other") == PASSWORD_DB_USER_NOT_FOUND);
    CHECK(password_db_delete_user(second, "zoe") == PASSWORD_DB_USER_NOT_FOUND);
    CHECK(password_db_verify_user(second, "Alice", "other") == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "bob", "replacement") == PASSWORD_DB_OK);
    puts("PASS: forced SQL failure atomicity, delete isolation and statement cleanup");

    password_db_close(first);
    first = NULL;
    password_db_close(second);
    second = NULL;
    CHECK(password_db_open(path, &first) == PASSWORD_DB_OK);
    CHECK(password_db_open(path, &second) == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(first, "bob", "replacement") == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(first, "bob", "original") == PASSWORD_DB_PASSWORD_MISMATCH);
    CHECK(password_db_verify_user(second, "zoe", "other") == PASSWORD_DB_USER_NOT_FOUND);
    list = (struct user_list){0};
    CHECK(password_db_list_users(second, collect_user, &list) == PASSWORD_DB_OK);
    CHECK(list.count == 2 && strcmp(list.names[0], "Alice") == 0 && strcmp(list.names[1], "bob") == 0);
    puts("PASS: change/delete/list persistence and visibility through independent handles");

    CHECK(sqlite3_exec(inspection, "DROP TABLE users", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_change_password(first, "bob", "new") == PASSWORD_DB_SQLITE_ERROR);
    CHECK(password_db_delete_user(first, "bob") == PASSWORD_DB_SQLITE_ERROR);
    list = (struct user_list){0};
    CHECK(password_db_list_users(first, collect_user, &list) == PASSWORD_DB_SQLITE_ERROR);
    CHECK(list.count == 0);
    CHECK(password_db_init_schema(second) == PASSWORD_DB_OK);
    CHECK(password_db_add_user(second, "recovered", "original") == PASSWORD_DB_OK);
    CHECK(password_db_change_password(first, "recovered", "new") == PASSWORD_DB_OK);
    CHECK(password_db_verify_user(second, "recovered", "new") == PASSWORD_DB_OK);
    CHECK(password_db_delete_user(first, "recovered") == PASSWORD_DB_OK);
    CHECK(password_db_list_users(second, collect_user, &list) == PASSWORD_DB_OK);
    CHECK(list.count == 0);
    puts("PASS: missing-schema errors and recovery for all management APIs");
    result = EXIT_SUCCESS;

cleanup:
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        result = EXIT_FAILURE;
    }
    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(too_long, sizeof(too_long));
    password_db_close(first);
    password_db_close(second);
    return result;
}

int main(void) {
    char directory[] = "/tmp/cs469-password-db-XXXXXX";
    char path[256] = {0};
    char invalid_path[256];
    password_db_t *first = NULL;
    password_db_t *second = NULL;
    sqlite3 *inspection = NULL;
    int count = 0;
    int result = EXIT_FAILURE;
    int have_directory = 0;

    CHECK(mkdtemp(directory) != NULL);
    have_directory = 1;
    int n = snprintf(path, sizeof(path), "%s/users.sqlite", directory);
    CHECK(n > 0 && (size_t)n < sizeof(path));
    n = snprintf(invalid_path, sizeof(invalid_path), "%s/missing/users.sqlite", directory);
    CHECK(n > 0 && (size_t)n < sizeof(invalid_path));

    CHECK(password_db_open(NULL, &first) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(first == NULL);
    CHECK(password_db_open("", &first) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(first == NULL);
    CHECK(password_db_open(":memory:", &first) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(first == NULL);
    CHECK(password_db_open(path, NULL) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_open(NULL, NULL) == PASSWORD_DB_INVALID_ARGUMENT);
    CHECK(password_db_init_schema(NULL) == PASSWORD_DB_INVALID_ARGUMENT);
    password_db_close(NULL);
    puts("PASS: null arguments and non-filesystem paths");

    CHECK(password_db_open(invalid_path, &first) == PASSWORD_DB_SQLITE_ERROR);
    CHECK(first == NULL);
    CHECK(password_db_open(directory, &first) == PASSWORD_DB_SQLITE_ERROR);
    CHECK(first == NULL);
    puts("PASS: nonexistent parent and directory-as-database paths");

    CHECK(password_db_open(path, &first) == PASSWORD_DB_OK);
    CHECK(first != NULL);
    CHECK(sqlite3_open_v2(path, &inspection, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='users'", &count) == SQLITE_OK);
    CHECK(count == 0);
    puts("PASS: fresh open leaves schema initialization explicit");

    CHECK(password_db_init_schema(first) == PASSWORD_DB_OK);
    CHECK(password_db_init_schema(first) == PASSWORD_DB_OK);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='users'", &count) == SQLITE_OK);
    CHECK(count == 1);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM pragma_table_info('users') WHERE "
        "(name='id' AND type='INTEGER' AND pk=1) OR "
        "(name='username' AND type='TEXT' AND \"notnull\"=1) OR "
        "(name IN ('salt','password_hash') AND type='BLOB' AND \"notnull\"=1) OR "
        "(name='algorithm' AND type='TEXT' AND \"notnull\"=1) OR "
        "(name='iterations' AND type='INTEGER' AND \"notnull\"=1) OR "
        "(name IN ('created_at','updated_at') AND type='TEXT' AND \"notnull\"=1 "
        "AND dflt_value='CURRENT_TIMESTAMP')", &count) == SQLITE_OK);
    CHECK(count == 8);
    puts("PASS: schema creation, idempotence, and all required columns");

    const char *insert = "INSERT INTO users(username,salt,password_hash,algorithm,iterations) "
        "VALUES('test-user',X'0102',X'0304','test-only',1)";
    CHECK(sqlite3_exec(inspection, insert, NULL, NULL, NULL) == SQLITE_OK);
    CHECK(sqlite3_exec(inspection, insert, NULL, NULL, NULL) == SQLITE_CONSTRAINT);
    CHECK(sqlite3_extended_errcode(inspection) == SQLITE_CONSTRAINT_UNIQUE);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM users WHERE username='test-user' "
        "AND created_at IS NOT NULL AND updated_at IS NOT NULL", &count) == SQLITE_OK);
    CHECK(count == 1);
    puts("PASS: username uniqueness and timestamp defaults");

    password_db_close(first);
    first = NULL;
    CHECK(password_db_open(path, &first) == PASSWORD_DB_OK);
    CHECK(password_db_init_schema(first) == PASSWORD_DB_OK);
    CHECK(password_db_open(path, &second) == PASSWORD_DB_OK);
    CHECK(first != second);
    CHECK(password_db_init_schema(second) == PASSWORD_DB_OK);
    password_db_close(first);
    first = NULL;
    CHECK(password_db_init_schema(second) == PASSWORD_DB_OK);
    CHECK(query_int(inspection, "SELECT count(*) FROM users", &count) == SQLITE_OK);
    CHECK(count == 1);
    CHECK(query_int(inspection,
        "SELECT count(*) FROM pragma_integrity_check WHERE integrity_check <> 'ok'", &count) == SQLITE_OK);
    CHECK(count == 0);
    puts("PASS: reopen persistence and independent handles without corruption");

    /* A conflicting index makes CREATE TABLE fail. After removing it, the same
     * handle must still work, proving the error path leaves usable resources.
     */
    CHECK(sqlite3_exec(inspection,
        "DROP TABLE users; CREATE TABLE blocker(value); CREATE INDEX users ON blocker(value);",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_init_schema(second) == PASSWORD_DB_SQLITE_ERROR);
    CHECK(sqlite3_exec(inspection, "DROP INDEX users; DROP TABLE blocker;",
        NULL, NULL, NULL) == SQLITE_OK);
    CHECK(password_db_init_schema(second) == PASSWORD_DB_OK);
    puts("PASS: schema failure and recovery on the same handle");
    CHECK(test_passwords(path, inspection) == EXIT_SUCCESS);
    CHECK(test_management(path, inspection) == EXIT_SUCCESS);
    result = EXIT_SUCCESS;

cleanup:
    password_db_close(first);
    password_db_close(second);
    if (inspection != NULL && sqlite3_close_v2(inspection) != SQLITE_OK) {
        fprintf(stderr, "FAIL: closing inspection connection\n");
        result = EXIT_FAILURE;
    }
    if (path[0] != '\0' && access(path, F_OK) == 0 && unlink(path) != 0) {
        perror("remove temporary database");
        result = EXIT_FAILURE;
    }
    if (have_directory && rmdir(directory) != 0) {
        perror("remove temporary directory");
        result = EXIT_FAILURE;
    }
    if (result == EXIT_SUCCESS) {
        puts("All password database tests passed; temporary database removed.");
    }
    return result;
}
