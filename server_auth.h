/* Isolated authentication boundary; no SQLite handles or server lifecycle state. */
#ifndef SERVER_AUTH_H
#define SERVER_AUTH_H
#include "protocol.h"
#include <stddef.h>

typedef enum {
    SERVER_AUTH_OK = 0,
    SERVER_AUTH_BAD_REQUEST,
    SERVER_AUTH_FAILED,
    SERVER_AUTH_INTERNAL
} server_auth_result_t;

/* Decoded field spans include exactly one trailing NUL, with no embedded NUL
 * or padding: each span is 2..65 bytes (1..64 characters). Explicit sizes make
 * unterminated wire buffers safe to reject without strlen/unbounded reads.
 * Username: ASCII letters/digits/_/- only, matching password_db. Password:
 * printable ASCII (space through ~). No normalization or truncation.
 *
 * db_path is a borrowed, terminated filesystem path to a provisioned DB; future
 * server startup should supply it via --auth-db / server_config_t.auth_db_path.
 * Missing/unusable DB/config/schema is INTERNAL; no database/schema is created.
 * Each call owns a read-only DB handle from open through verify and close.
 * No shared handle, mutable global state, extra locks or plaintext copies.
 *
 * password is writable caller-owned storage; its full supplied span is cleansed
 * on EVERY return (unless NULL), including malformed/unterminated input. Caller
 * must still cleanse any remaining wire-buffer capacity and parse-error paths
 * that do not call this function. username/path are neither modified nor retained.
 * Password storage must not alias username/path. Buffers/path must remain valid
 * and unchanged during the call; independent
 * calls may run concurrently, using separate password buffers. Sizes must name
 * actual accessible allocations. NULL credentials => BAD_REQUEST. With valid
 * credentials, NULL/empty/invalid db_path => INTERNAL. No credentials are logged.
 */
server_auth_result_t server_auth_verify(const char *db_path,
    const char *username, size_t username_size, char *password, size_t password_size);

/* Explicit enum mapping, never boolean semantics. Unexpected values fail closed. */
error_code_t server_auth_to_error(server_auth_result_t result);
#endif
