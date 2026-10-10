/*
 * CS 469
 * SQLite password database lifecycle, schema, user insertion and verification.
 * This module has no server, admin CLI, protocol, or replication integration.
 */
#include "password_db.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct password_db {
    sqlite3 *connection;
};

/* OWASP Password Storage Cheat Sheet recommends 600000 for PBKDF2-HMAC-SHA256:
 * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 * The verification ceiling bounds corrupted-record CPU cost, not new-user cost.
 */
#define PASSWORD_DB_PBKDF2_ITERATIONS 600000
#define PASSWORD_DB_MAX_ITERATIONS 10000000
#define PASSWORD_DB_SALT_SIZE 16
#define PASSWORD_DB_KEY_SIZE 32
#define PASSWORD_DB_USERNAME_MAX 64
#define PASSWORD_DB_PASSWORD_MAX 4096
#define PASSWORD_DB_ALGORITHM "PBKDF2-HMAC-SHA256"

static const char schema[] =
    "CREATE TABLE IF NOT EXISTS users ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "username TEXT NOT NULL UNIQUE,"
    "salt BLOB NOT NULL,"
    "password_hash BLOB NOT NULL,"
    "algorithm TEXT NOT NULL,"
    "iterations INTEGER NOT NULL,"
    "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
    "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
    ");";

/* Generic SQLite error strings cannot include usernames, passwords, or paths. */
static int sqlite_failure(const char *operation, int rc) {
    fprintf(stderr, "password_db: %s: %s\n", operation, sqlite3_errstr(rc));
    return (rc & 0xff) == SQLITE_NOMEM
        ? PASSWORD_DB_NO_MEMORY : PASSWORD_DB_SQLITE_ERROR;
}

void password_db_close(password_db_t *db) {
    if (db == NULL) {
        return;
    }

    /* No prepared statements escape this module. close_v2 also safely handles
     * a connection returned by a failed open; NULL connections are permitted.
     */
    int rc = sqlite3_close_v2(db->connection);
    if (rc != SQLITE_OK) {
        (void)sqlite_failure("close", rc);
    }
    free(db);
}

int password_db_open(const char *path, password_db_t **out) {
    if (out == NULL) {
        return PASSWORD_DB_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (path == NULL || path[0] == '\0' || strcmp(path, ":memory:") == 0) {
        return PASSWORD_DB_INVALID_ARGUMENT;
    }
    if (sqlite3_threadsafe() == 0) {
        return sqlite_failure("thread-enabled SQLite required", SQLITE_MISUSE);
    }

    password_db_t *db = calloc(1, sizeof(*db));
    if (db == NULL) {
        return PASSWORD_DB_NO_MEMORY;
    }

    int rc = sqlite3_open_v2(path, &db->connection,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX |
        SQLITE_OPEN_PRIVATECACHE, NULL);
    if (rc != SQLITE_OK) {
        int result = sqlite_failure("open", rc);
        password_db_close(db);
        return result;
    }

    /* Extended step results identify uniqueness errors without a racy separate
     * read of connection-wide error state when a handle is used by threads.
     */
    rc = sqlite3_extended_result_codes(db->connection, 1);
    if (rc == SQLITE_OK) {
        rc = sqlite3_busy_timeout(db->connection, 5000);
    }
    if (rc != SQLITE_OK) {
        int result = sqlite_failure("configure lock timeout", rc);
        password_db_close(db);
        return result;
    }

    *out = db;
    return PASSWORD_DB_OK;
}

int password_db_init_schema(password_db_t *db) {
    if (db == NULL) {
        return PASSWORD_DB_INVALID_ARGUMENT;
    }

    /* One atomic DDL statement; sqlite3_exec finalizes its internal statements.
     * No detailed error message is allocated or printed, to avoid record data.
     */
    int rc = sqlite3_exec(db->connection, schema, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_failure("initialize schema", rc);
    }
    return PASSWORD_DB_OK;
}

/* Bounded scans centralize the input policy without making password copies. */
static int valid_username(const char *username) {
    if (username == NULL) {
        return 0;
    }
    size_t i;
    for (i = 0; i <= PASSWORD_DB_USERNAME_MAX; ++i) {
        unsigned char c = (unsigned char)username[i];
        if (c == '\0') {
            break;
        }
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return 0;
        }
    }
    return i > 0 && i <= PASSWORD_DB_USERNAME_MAX;
}

static int valid_inputs(password_db_t *db, const char *username,
                        const char *password, int *password_length) {
    if (db == NULL || !valid_username(username) || password == NULL) {
        return 0;
    }
    size_t i;
    for (i = 0; i <= PASSWORD_DB_PASSWORD_MAX && password[i] != '\0'; ++i) {
    }
    if (i == 0 || i > PASSWORD_DB_PASSWORD_MAX) {
        return 0;
    }
    *password_length = (int)i;
    return 1;
}

/* Account operations return errors without printing account-existence clues. */
static int database_result(int rc) {
    return (rc & 0xff) == SQLITE_NOMEM
        ? PASSWORD_DB_NO_MEMORY : PASSWORD_DB_SQLITE_ERROR;
}

static int finish_statement(sqlite3_stmt *stmt, int result) {
    int rc = sqlite3_finalize(stmt);
    /* finalize may repeat the step error already mapped (e.g. USER_EXISTS). */
    if (rc != SQLITE_OK && result == PASSWORD_DB_OK) {
        return database_result(rc);
    }
    return result;
}

/* Use SQLite's existing recursive connection mutex to keep step + changes
 * together. Otherwise another thread using this handle could overwrite the
 * connection-wide change count between those calls. No new mutex is allocated.
 */
static int step_mutation(password_db_t *db, sqlite3_stmt *stmt, int *changed) {
    sqlite3_mutex *mutex = sqlite3_db_mutex(db->connection);
    sqlite3_mutex_enter(mutex);
    int rc = sqlite3_step(stmt);
    *changed = rc == SQLITE_DONE ? sqlite3_changes(db->connection) : 0;
    sqlite3_mutex_leave(mutex);
    return rc;
}

/* Insertion and password replacement share validation, salt generation, KDF,
 * bindings and cleansing; only the atomic SQL mutation differs.
 */
static int store_password(password_db_t *db, const char *username,
                           const char *password, int replace) {
    int password_length;
    if (!valid_inputs(db, username, password, &password_length)) {
        return PASSWORD_DB_INVALID_ARGUMENT;
    }

    unsigned char salt[PASSWORD_DB_SALT_SIZE] = {0};
    unsigned char key[PASSWORD_DB_KEY_SIZE] = {0};
    sqlite3_stmt *stmt = NULL;
    int result = PASSWORD_DB_CRYPTO_ERROR;
    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        PKCS5_PBKDF2_HMAC(password, password_length, salt, sizeof(salt),
            PASSWORD_DB_PBKDF2_ITERATIONS, EVP_sha256(), sizeof(key), key) != 1) {
        goto cleanup;
    }

    const char *sql = replace
        ? "UPDATE users SET salt=?2,password_hash=?3,algorithm=?4,iterations=?5,"
          "updated_at=CURRENT_TIMESTAMP WHERE username=?1"
        : "INSERT INTO users(username,salt,password_hash,algorithm,iterations) "
          "VALUES(?1,?2,?3,?4,?5)";
    int changed = 0;
    int rc = sqlite3_prepare_v2(db->connection, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_blob(stmt, 2, salt, sizeof(salt), SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_blob(stmt, 3, key, sizeof(key), SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 4, PASSWORD_DB_ALGORITHM, -1, SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 5, PASSWORD_DB_PBKDF2_ITERATIONS);
    }
    if (rc == SQLITE_OK) {
        rc = step_mutation(db, stmt, &changed);
    }
    if (rc == SQLITE_DONE) {
        result = replace && changed == 0 ? PASSWORD_DB_USER_NOT_FOUND : PASSWORD_DB_OK;
    } else {
        result = !replace && rc == SQLITE_CONSTRAINT_UNIQUE
            ? PASSWORD_DB_USER_EXISTS : database_result(rc);
    }

cleanup:
    /* STATIC bindings avoid extra key copies and remain valid until finalized. */
    result = finish_statement(stmt, result);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(salt, sizeof(salt));
    return result;
}

int password_db_add_user(password_db_t *db, const char *username,
                         const char *password) {
    return store_password(db, username, password, 0);
}

int password_db_change_password(password_db_t *db, const char *username,
                                const char *new_password) {
    return store_password(db, username, new_password, 1);
}

int password_db_delete_user(password_db_t *db, const char *username) {
    if (db == NULL || !valid_username(username)) {
        return PASSWORD_DB_INVALID_ARGUMENT;
    }
    sqlite3_stmt *stmt = NULL;
    int changed = 0;
    int rc = sqlite3_prepare_v2(db->connection,
        "DELETE FROM users WHERE username=?1", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = step_mutation(db, stmt, &changed);
    }
    int result = rc == SQLITE_DONE
        ? (changed == 0 ? PASSWORD_DB_USER_NOT_FOUND : PASSWORD_DB_OK)
        : database_result(rc);
    return finish_statement(stmt, result);
}

int password_db_list_users(password_db_t *db,
                           password_db_user_callback callback, void *context) {
    if (db == NULL || callback == NULL) {
        return PASSWORD_DB_INVALID_ARGUMENT;
    }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db->connection,
        "SELECT username FROM users ORDER BY username COLLATE BINARY", -1, &stmt, NULL);
    int result = PASSWORD_DB_OK;
    if (rc != SQLITE_OK) {
        return finish_statement(stmt, database_result(rc));
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_TEXT) {
            result = PASSWORD_DB_INVALID_RECORD;
            break;
        }
        const char *username = (const char *)sqlite3_column_text(stmt, 0);
        if (username == NULL) {
            result = PASSWORD_DB_NO_MEMORY;
            break;
        }
        if (!valid_username(username) ||
            (size_t)sqlite3_column_bytes(stmt, 0) != strlen(username)) {
            result = PASSWORD_DB_INVALID_RECORD;
            break;
        }
        if (callback(username, context) != 0) {
            result = PASSWORD_DB_STOPPED;
            break;
        }
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        result = database_result(rc);
    }
    return finish_statement(stmt, result);
}

int password_db_verify_user(password_db_t *db, const char *username,
                            const char *password) {
    int password_length;
    if (!valid_inputs(db, username, password, &password_length)) {
        return PASSWORD_DB_INVALID_ARGUMENT;
    }

    unsigned char salt[PASSWORD_DB_SALT_SIZE] = {0};
    unsigned char expected[PASSWORD_DB_KEY_SIZE] = {0};
    unsigned char derived[PASSWORD_DB_KEY_SIZE] = {0};
    sqlite3_stmt *stmt = NULL;
    int iterations = 0;
    int result;
    int rc = sqlite3_prepare_v2(db->connection,
        "SELECT salt,password_hash,algorithm,iterations FROM users WHERE username=?1",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
    }
    if (rc != SQLITE_ROW) {
        result = rc == SQLITE_DONE ? PASSWORD_DB_USER_NOT_FOUND : database_result(rc);
        goto cleanup;
    }

    /* Check SQLite types before access so coercion cannot hide malformed data. */
    result = PASSWORD_DB_INVALID_RECORD;
    if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB ||
        sqlite3_column_type(stmt, 1) != SQLITE_BLOB ||
        sqlite3_column_type(stmt, 2) != SQLITE_TEXT ||
        sqlite3_column_type(stmt, 3) != SQLITE_INTEGER ||
        sqlite3_column_bytes(stmt, 0) != sizeof(salt) ||
        sqlite3_column_bytes(stmt, 1) != sizeof(expected)) {
        goto cleanup;
    }
    sqlite3_int64 stored_iterations = sqlite3_column_int64(stmt, 3);
    if (stored_iterations < 1 || stored_iterations > PASSWORD_DB_MAX_ITERATIONS) {
        goto cleanup;
    }
    const unsigned char *algorithm = sqlite3_column_text(stmt, 2);
    const void *stored_salt = sqlite3_column_blob(stmt, 0);
    const void *stored_key = sqlite3_column_blob(stmt, 1);
    if (algorithm == NULL || stored_salt == NULL || stored_key == NULL) {
        result = PASSWORD_DB_NO_MEMORY;
        goto cleanup;
    }
    if (sqlite3_column_bytes(stmt, 2) != sizeof(PASSWORD_DB_ALGORITHM) - 1 ||
        strcmp((const char *)algorithm, PASSWORD_DB_ALGORITHM) != 0) {
        result = PASSWORD_DB_UNSUPPORTED_ALGORITHM;
        goto cleanup;
    }
    iterations = (int)stored_iterations;
    memcpy(salt, stored_salt, sizeof(salt));
    memcpy(expected, stored_key, sizeof(expected));

    /* Release the read transaction before the expensive KDF. Local copies
     * preserve the record snapshot and are cleansed on every exit path.
     */
    result = finish_statement(stmt, PASSWORD_DB_OK);
    stmt = NULL;
    if (result != PASSWORD_DB_OK) {
        goto cleanup;
    }
    if (PKCS5_PBKDF2_HMAC(password, password_length, salt, sizeof(salt),
            iterations, EVP_sha256(), sizeof(derived), derived) != 1) {
        result = PASSWORD_DB_CRYPTO_ERROR;
        goto cleanup;
    }
    result = CRYPTO_memcmp(derived, expected, sizeof(derived)) == 0
        ? PASSWORD_DB_OK : PASSWORD_DB_PASSWORD_MISMATCH;

cleanup:
    result = finish_statement(stmt, result);
    OPENSSL_cleanse(derived, sizeof(derived));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(salt, sizeof(salt));
    return result;
}
