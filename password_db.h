/*
 * CS 469
 * Password database lifecycle and schema interface.
 * Database connections are opaque and owned by the caller until closed.
 */
#ifndef PASSWORD_DB_H
#define PASSWORD_DB_H

typedef struct password_db password_db_t;

enum {
    PASSWORD_DB_OK = 0,
    PASSWORD_DB_INVALID_ARGUMENT = 1,
    PASSWORD_DB_NO_MEMORY = 2,
    PASSWORD_DB_SQLITE_ERROR = 3,
    PASSWORD_DB_USER_EXISTS = 4,
    PASSWORD_DB_USER_NOT_FOUND = 5,
    PASSWORD_DB_PASSWORD_MISMATCH = 6,
    PASSWORD_DB_CRYPTO_ERROR = 7,
    PASSWORD_DB_UNSUPPORTED_ALGORITHM = 8,
    PASSWORD_DB_INVALID_RECORD = 9
};

/*
 * Open/create a database at an explicit filesystem path. Schema initialization
 * is a separate step. On success, *out owns a new handle; close it exactly once.
 * On failure, *out is NULL when out is non-NULL. NULL/empty paths, ":memory:",
 * and NULL out return PASSWORD_DB_INVALID_ARGUMENT. Allocation failures return
 * PASSWORD_DB_NO_MEMORY; other SQLite failures return PASSWORD_DB_SQLITE_ERROR.
 * Pass an unused output slot: this function does not close a previous *out.
 *
 * Each handle owns a serialized SQLite connection (thread-enabled SQLite is
 * required). Separate handles may use the same database. Lock contention waits
 * up to five seconds before returning an error. Callers must ensure close does
 * not overlap any use of that handle; no global connection is created.
 */
int password_db_open(const char *path, password_db_t **out);

/*
 * Create the users table if absent. Repeated calls preserve existing data.
 * Returns PASSWORD_DB_OK, PASSWORD_DB_INVALID_ARGUMENT for NULL, or the memory/
 * SQLite failure codes above. Existing schemas are not validated or migrated.
 * SQLite diagnostics report the operation and generic error, never record data.
 */
int password_db_init_schema(password_db_t *db);

/*
 * Add a user to an initialized database. Usernames are case-sensitive, 1-64
 * ASCII letters/digits/underscores/hyphens only (no periods or path separators).
 * Passwords are 1-4096 bytes in a NUL-terminated C string; all non-NUL byte values
 * are accepted without normalization. Embedded NULs cannot be represented.
 * Neither input is modified or retained. The caller owns/clears its password.
 * New records use PBKDF2-HMAC-SHA256, a random 16-byte salt, a 32-byte key, and
 * 600000 iterations. No plaintext password is stored or logged.
 *
 * Returns OK, INVALID_ARGUMENT (NULL db/input or invalid username/password),
 * USER_EXISTS (no replacement), NO_MEMORY, SQLITE_ERROR (including missing
 * schema or lock timeout), or CRYPTO_ERROR (random generation/KDF failure).
 * Add/verify do not log account-specific outcomes. These are internal result
 * codes; a future authentication endpoint should conceal account existence.
 */
int password_db_add_user(password_db_t *db, const char *username,
                         const char *password);

/*
 * Verify using stored salt/hash/algorithm/iterations, with constant-time hash
 * comparison. Input and ownership rules match add_user. Returns OK,
 * USER_NOT_FOUND, PASSWORD_MISMATCH, INVALID_ARGUMENT, NO_MEMORY, SQLITE_ERROR,
 * CRYPTO_ERROR, UNSUPPORTED_ALGORITHM, or INVALID_RECORD (malformed parameters).
 * Currently accepts 16-byte salts, 32-byte hashes and stored iteration counts
 * from 1 through 10000000; the upper bound limits work from corrupted records.
 * No automatic rehashing occurs. Lookup/validation timing is not equalized
 * across missing users, malformed records and existing users.
 */
int password_db_verify_user(password_db_t *db, const char *username,
                            const char *password);

/* Release the connection and handle. NULL is a no-op; other handles are invalid
 * after this call. All operations using this handle must already have finished.
 */
void password_db_close(password_db_t *db);

#endif /* PASSWORD_DB_H */
