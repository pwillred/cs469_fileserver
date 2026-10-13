#include "protocol.h"
#include "server.h"
#include "server_protocol_io.h"
#include "server_protocol_fields.h"

#include <openssl/ssl.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compatibility signatures for the partner write handlers. Use the isolated
 * SSL-first adapter because production dispatch leaves sockets nonblocking. */
int read_fully(SSL* ssl, void* buf, size_t len, int timeout_sec) {
    server_protocol_io_t state;
    server_read_io_t io;
    if (server_protocol_io_init(&state, ssl, timeout_sec * 1000, &io) != 0) return -1;
    return io.read_exact(io.state, buf, len);
}
int write_fully(SSL* ssl, const void* buf, size_t len) {
    server_protocol_io_t state;
    server_read_io_t io;
    if (server_protocol_io_init(&state, ssl, DEFAULT_TIMEOUT * 1000, &io) != 0) return -1;
    return io.write_all(io.state, buf, len);
}
int send_error(SSL* ssl, error_code_t err) {
    uint8_t byte = server_status_byte(err);
    return write_fully(ssl, &byte, sizeof(byte));
}

/* validate_filename takes a filename, and ensures that it meets basic sanity requirements. */
int validate_filename(const char* filename) {
    /* Reject any NULL filenames. */
    if (!filename) {
        return 0;
    }
    
    /* Ensure the filename isn't empty, and that it is within the specified length. */
    size_t len = strlen(filename);
    if (len == 0 || len > MAX_FILENAME_LEN) {
        return 0;
    }
    
    /* Frozen filename policy: printable ASCII and no path separators. */
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)filename[i] < 32 || (unsigned char)filename[i] > 126 ||
            filename[i] == '/' || filename[i] == '\\') {
            return 0;
        }
    }
    
    /* Similarly, '.' and '..' are illegal filenames. */
    if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
        return 0;
    }
    
    return 1;
}

/* get_user_dir takes the specified username and root directory of the service, and returns
 * the full path to the user's directory. */
char* get_user_dir(const char* username, const char* data_dir) {
    size_t len = strlen(data_dir) + 1 + strlen(username) + 1;
    char* dir = malloc(len);
    if (!dir) {
        return NULL;
    }
    snprintf(dir, len, "%s/%s", data_dir, username);
    return dir;
}
