#include "server_auth.h"
#include "password_db.h"
#include <openssl/crypto.h>

static int valid_field(const char *value, size_t size, int username) {
    if (value == NULL || size < 2 || size > 65 || value[size - 1] != '\0') return 0;
    for (size_t i = 0; i < size - 1; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (username) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
        } else if (c < 32 || c > 126) return 0;
    }
    return 1;
}

static server_auth_result_t verify_decoded(const char *path, const char *username,
                                          size_t username_size, const char *password,
                                          size_t password_size) {
    if (!valid_field(username, username_size, 1) || !valid_field(password, password_size, 0))
        return SERVER_AUTH_BAD_REQUEST;
    password_db_t *db = NULL;
    if (password_db_open_existing(path, &db) != PASSWORD_DB_OK) return SERVER_AUTH_INTERNAL;
    int result = password_db_verify_user(db, username, password);
    password_db_close(db);
    switch (result) {
        case PASSWORD_DB_OK: return SERVER_AUTH_OK;
        case PASSWORD_DB_USER_NOT_FOUND:
        case PASSWORD_DB_PASSWORD_MISMATCH: return SERVER_AUTH_FAILED;
        /* Inputs have already passed the DB policy; INVALID_ARGUMENT here is
         * an unexpected internal contract failure, not malformed client input. */
        case PASSWORD_DB_INVALID_ARGUMENT:
        case PASSWORD_DB_SQLITE_ERROR:
        case PASSWORD_DB_CRYPTO_ERROR:
        case PASSWORD_DB_NO_MEMORY:
        case PASSWORD_DB_UNSUPPORTED_ALGORITHM:
        case PASSWORD_DB_INVALID_RECORD:
        default: return SERVER_AUTH_INTERNAL;
    }
}

server_auth_result_t server_auth_verify(const char *db_path,
    const char *username, size_t username_size, char *password, size_t password_size) {
    server_auth_result_t result = verify_decoded(db_path, username, username_size, password, password_size);
    if (password != NULL) OPENSSL_cleanse(password, password_size);
    return result;
}

error_code_t server_auth_to_error(server_auth_result_t result) {
    switch (result) {
        case SERVER_AUTH_OK: return ERR_OK;
        case SERVER_AUTH_BAD_REQUEST: return ERR_BAD_REQUEST;
        case SERVER_AUTH_FAILED: return ERR_AUTH_FAILED;
        case SERVER_AUTH_INTERNAL:
        default: return ERR_INTERNAL;
    }
}
