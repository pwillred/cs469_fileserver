/* Client codec for the frozen working contract; independent of server headers. */
#ifndef CLIENT_PROTOCOL_H
#define CLIENT_PROTOCOL_H
#include "client_transport.h"
#include <stdint.h>
#define CLIENT_WIRE_CREDENTIAL_MAX 64
#define CLIENT_WIRE_FILENAME_MAX 256
#define CLIENT_LIST_MAX_ENTRIES 10000

typedef enum {
    CLIENT_STATUS_OK, CLIENT_STATUS_AUTH_FAILED, CLIENT_STATUS_NOT_FOUND,
    CLIENT_STATUS_EXISTS, CLIENT_STATUS_BAD_REQUEST, CLIENT_STATUS_TOO_LARGE,
    CLIENT_STATUS_REPLICATION_FAILED, CLIENT_STATUS_INTERNAL
} client_status_t;

typedef enum { CLIENT_FIELD_CREDENTIAL, CLIENT_FIELD_FILENAME } client_field_t;
/* Nonempty printable ASCII only. Filenames also exclude /, backslash, . and .. .
 * C strings must be terminated; validation scans at most limit + 1 bytes.
 * All codec functions return CLIENT_TRANSPORT_* results. Unknown status is a
 * PROTOCOL_ERROR and leaves the output unchanged. No credentials are copied. */
int client_protocol_validate(const char *value, client_field_t field);
int client_status_decode(uint8_t raw, client_status_t *out);
const char *client_status_description(client_status_t status);
int client_protocol_write_string(client_connection_t *c, const char *value, client_field_t field);
int client_protocol_write_u32(client_connection_t *c, uint32_t value);
int client_protocol_read_u32(client_connection_t *c, uint32_t *out);
int client_protocol_read_status(client_connection_t *c, client_status_t *out);
/* Caller supplies at least 257 bytes; malformed remote strings are protocol errors. */
int client_protocol_read_filename(client_connection_t *c, char out[CLIENT_WIRE_FILENAME_MAX + 1]);
/* Validates every field before writing anything. Verbs have no NUL or padding.
 * UPLOAD includes size before filename; LIST ignores filename and size. */
int client_protocol_write_request(client_connection_t *c, client_command_t command,
    const char *username, const char *password, const char *filename, uint32_t size);
#endif
