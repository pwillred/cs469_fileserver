#include "client_protocol.h"
#include <string.h>

int client_protocol_validate(const char *value, client_field_t field) {
    if (value == NULL || (field != CLIENT_FIELD_CREDENTIAL && field != CLIENT_FIELD_FILENAME))
        return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    size_t limit = field == CLIENT_FIELD_CREDENTIAL ? CLIENT_WIRE_CREDENTIAL_MAX : CLIENT_WIRE_FILENAME_MAX;
    size_t n;
    for (n = 0; n <= limit; ++n) {
        unsigned char ch = (unsigned char)value[n];
        if (ch == 0) break;
        if (ch < 32 || ch > 126 || (field == CLIENT_FIELD_FILENAME && (ch == '/' || ch == '\\')))
            return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    }
    if (n == 0 || n > limit || (field == CLIENT_FIELD_FILENAME &&
        (strcmp(value, ".") == 0 || strcmp(value, "..") == 0))) return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    return CLIENT_TRANSPORT_OK;
}
int client_status_decode(uint8_t raw, client_status_t *out) {
    if (out == NULL) return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    if (raw > CLIENT_STATUS_INTERNAL) return CLIENT_TRANSPORT_PROTOCOL_ERROR;
    *out = (client_status_t)raw;
    return CLIENT_TRANSPORT_OK;
}
const char *client_status_description(client_status_t status) {
    switch (status) {
        case CLIENT_STATUS_OK: return "Success.";
        case CLIENT_STATUS_AUTH_FAILED: return "Authentication failed.";
        case CLIENT_STATUS_NOT_FOUND: return "File not found.";
        case CLIENT_STATUS_EXISTS: return "Remote file already exists.";
        case CLIENT_STATUS_BAD_REQUEST: return "Request rejected as malformed.";
        case CLIENT_STATUS_TOO_LARGE: return "File exceeds server limit.";
        case CLIENT_STATUS_REPLICATION_FAILED: return "Replication failed; write was not completed.";
        case CLIENT_STATUS_INTERNAL: return "Server returned an internal error.";
        default: return "Protocol error: invalid response.";
    }
}
int client_protocol_write_string(client_connection_t *c, const char *value, client_field_t field) {
    int rc = client_protocol_validate(value, field);
    return rc == CLIENT_TRANSPORT_OK ? client_connection_write_all(c, value, strlen(value) + 1) : rc;
}
int client_protocol_write_u32(client_connection_t *c, uint32_t value) {
    uint8_t bytes[4] = {(uint8_t)(value >> 24), (uint8_t)(value >> 16), (uint8_t)(value >> 8), (uint8_t)value};
    return client_connection_write_all(c, bytes, sizeof(bytes));
}
int client_protocol_read_u32(client_connection_t *c, uint32_t *out) {
    if (out == NULL) return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    uint8_t b[4];
    int rc = client_connection_read_exact(c, b, sizeof(b));
    if (rc == CLIENT_TRANSPORT_OK)
        *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
    return rc;
}
int client_protocol_read_status(client_connection_t *c, client_status_t *out) {
    if (out == NULL) return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    uint8_t raw;
    int rc = client_connection_read_exact(c, &raw, 1);
    return rc == CLIENT_TRANSPORT_OK ? client_status_decode(raw, out) : rc;
}
int client_protocol_read_filename(client_connection_t *c, char out[CLIENT_WIRE_FILENAME_MAX + 1]) {
    if (out == NULL) return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    for (size_t i = 0; i <= CLIENT_WIRE_FILENAME_MAX; ++i) {
        int rc = client_connection_read_exact(c, out + i, 1);
        if (rc != CLIENT_TRANSPORT_OK) return rc;
        if (out[i] == 0) return client_protocol_validate(out, CLIENT_FIELD_FILENAME) == CLIENT_TRANSPORT_OK
            ? CLIENT_TRANSPORT_OK : CLIENT_TRANSPORT_PROTOCOL_ERROR;
    }
    return CLIENT_TRANSPORT_PROTOCOL_ERROR;
}
int client_protocol_write_request(client_connection_t *c, client_command_t command,
    const char *username, const char *password, const char *filename, uint32_t size) {
    const char *verb;
    switch (command) {
        case CLIENT_COMMAND_LIST: verb = "LIST"; break;
        case CLIENT_COMMAND_UPLOAD: verb = "UPLOAD"; break;
        case CLIENT_COMMAND_DOWNLOAD: verb = "DOWNLOAD"; break;
        case CLIENT_COMMAND_DELETE: verb = "DELETE"; break;
        default: return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    }
    if (client_protocol_validate(username, CLIENT_FIELD_CREDENTIAL) != CLIENT_TRANSPORT_OK ||
        client_protocol_validate(password, CLIENT_FIELD_CREDENTIAL) != CLIENT_TRANSPORT_OK ||
        (command != CLIENT_COMMAND_LIST && client_protocol_validate(filename, CLIENT_FIELD_FILENAME) != CLIENT_TRANSPORT_OK))
        return CLIENT_TRANSPORT_INVALID_ARGUMENT;
    int rc = client_connection_write_all(c, verb, strlen(verb));
    if (rc == CLIENT_TRANSPORT_OK) rc = client_protocol_write_string(c, username, CLIENT_FIELD_CREDENTIAL);
    if (rc == CLIENT_TRANSPORT_OK) rc = client_protocol_write_string(c, password, CLIENT_FIELD_CREDENTIAL);
    if (rc == CLIENT_TRANSPORT_OK && command == CLIENT_COMMAND_UPLOAD) rc = client_protocol_write_u32(c, size);
    if (rc == CLIENT_TRANSPORT_OK && command != CLIENT_COMMAND_LIST)
        rc = client_protocol_write_string(c, filename, CLIENT_FIELD_FILENAME);
    return rc;
}
