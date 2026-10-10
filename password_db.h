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
    PASSWORD_DB_INVALID_RECORD = 9,
    PASSWORD_DB_STOPPED = 10
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

/*
 * Replace an existing user's credentials using the same input policy and KDF
 * defaults as add_user. Generates a fresh salt, refreshes updated_at, and keeps
 * id, username and created_at. Crypto completes before a single atomic UPDATE;
 * failure leaves the existing record unchanged. No old password is required:
 * this is a privileged administrative primitive, not an authentication API.
 * Returns OK, INVALID_ARGUMENT, USER_NOT_FOUND, NO_MEMORY, SQLITE_ERROR or
 * CRYPTO_ERROR. The caller owns and must clear new_password as appropriate.
 */
int password_db_change_password(password_db_t *db, const char *username,
                                const char *new_password);

/* Delete only the named database record (no filesystem operations). Username
 * policy matches add_user. Returns OK, INVALID_ARGUMENT, USER_NOT_FOUND,
 * NO_MEMORY or SQLITE_ERROR. A missing user is not treated as success.
 */
int password_db_delete_user(password_db_t *db, const char *username);

typedef int (*password_db_user_callback)(const char *username, void *context);

/*
 * Enumerate usernames only, in ascending SQLite BINARY (case-sensitive) order.
 * callback returns zero to continue; any nonzero value stops enumeration and
 * returns PASSWORD_DB_STOPPED. An empty list returns OK without callbacks.
 * username is borrowed, read-only, and valid only during that callback; copy it
 * if needed later. context is passed through unchanged and may be NULL.
 * Callbacks must not close/reenter this handle or mutate the database. A read
 * transaction remains active during callbacks, so callbacks should be brief.
 * NULL db/callback returns INVALID_ARGUMENT. Other results: OK, STOPPED,
 * NO_MEMORY, SQLITE_ERROR or INVALID_RECORD for malformed stored usernames.
 * On errors, earlier callbacks may already have run; their effects are not
 * rolled back. No salts, hashes or KDF metadata are selected or returned.
 */
int password_db_list_users(password_db_t *db,
                           password_db_user_callback callback, void *context);

/* Release the connection and handle. NULL is a no-op; other handles are invalid
 * after this call. All operations using this handle must already have finished.
 */
void password_db_close(password_db_t *db);

#endif /* PASSWORD_DB_H */
