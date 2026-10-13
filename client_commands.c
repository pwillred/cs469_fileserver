#define _POSIX_C_SOURCE 200809L
#include "client_commands.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TRANSFER_CHUNK 16384
static client_command_result_t local_error(const char *message) {
    return (client_command_result_t){CLIENT_RESULT_LOCAL, 0, CLIENT_STATUS_OK, message};
}
static client_command_result_t wire_error(int rc) {
    return (client_command_result_t){rc == CLIENT_TRANSPORT_PROTOCOL_ERROR ? CLIENT_RESULT_PROTOCOL : CLIENT_RESULT_TRANSPORT,
        rc, CLIENT_STATUS_OK, rc == CLIENT_TRANSPORT_PROTOCOL_ERROR ? "Protocol error: invalid response." : client_transport_result_string(rc)};
}
/* Only availability failures qualify, and only before the initial status.
 * TLS negotiation/configuration/security and malformed replies fail closed. */
static int failover_eligible(int rc) {
    switch (rc) {
        case CLIENT_TRANSPORT_RESOLVE_ERROR:
        case CLIENT_TRANSPORT_CONNECT_ERROR:
        case CLIENT_TRANSPORT_TIMEOUT:
        case CLIENT_TRANSPORT_IO_ERROR:
        case CLIENT_TRANSPORT_EOF: return 1;
        default: return 0;
    }
}
/* One endpoint-specific attempt, ending at the status boundary. The caller
 * closes any connection on failure. Unknown status bytes return PROTOCOL_ERROR,
 * so neither a valid application rejection nor malformed status can fail over. */
static int request_status(const client_options_t *o, const client_endpoint_t *endpoint,
                          const char *password, uint32_t size,
                          client_connection_t **c, client_status_t *status) {
    int rc = client_connection_open(endpoint, o->deployment.ca_file, c);
    if (rc == CLIENT_TRANSPORT_OK)
        rc = client_protocol_write_request(*c, o->command, o->username, password, o->remote_name, size);
    if (rc == CLIENT_TRANSPORT_OK) rc = client_protocol_read_status(*c, status);
    return rc;
}
static client_command_result_t execute(const client_options_t *o, const char *password, FILE *output) {
    client_command_result_t result = {CLIENT_RESULT_OK, 0, CLIENT_STATUS_OK, "Success."};
    client_connection_t *c = NULL;
    int source = -1, target = -1, directory = -1, temp_exists = 0;
    int replica_attempted = 0;
    char *path = NULL, *basename = NULL;
    char temporary[64] = {0};
    uint32_t size = 0;
    if (o == NULL || output == NULL || o->command < CLIENT_COMMAND_LIST || o->command > CLIENT_COMMAND_DELETE)
        return local_error("Invalid command arguments.");
    if (client_protocol_validate(o->username, CLIENT_FIELD_CREDENTIAL) != CLIENT_TRANSPORT_OK)
        return local_error("Username must contain 1–64 printable ASCII characters.");
    if (client_protocol_validate(password, CLIENT_FIELD_CREDENTIAL) != CLIENT_TRANSPORT_OK)
        return local_error("Password must contain 1–64 printable ASCII characters for the wire protocol.");
    if (o->command != CLIENT_COMMAND_LIST && client_protocol_validate(o->remote_name, CLIENT_FIELD_FILENAME) != CLIENT_TRANSPORT_OK)
        return local_error("Remote filename must contain 1–256 printable ASCII characters without path separators; . and .. are invalid.");
    if ((o->command == CLIENT_COMMAND_UPLOAD || o->command == CLIENT_COMMAND_DOWNLOAD) &&
        (o->local_path == NULL || o->local_path[0] == 0)) return local_error("Local path is required.");
#define LOCAL(message) do { result = local_error(message); goto done; } while (0)
#define WIRE(expression) do { int wire_rc = (expression); if (wire_rc != CLIENT_TRANSPORT_OK) { result = wire_error(wire_rc); goto done; } } while (0)
#define STATUS() do { client_status_t status; WIRE(client_protocol_read_status(c, &status)); \
    if (status != CLIENT_STATUS_OK) { result = (client_command_result_t){CLIENT_RESULT_STATUS, 0, status, client_status_description(status)}; goto done; } } while (0)
    if (o->command == CLIENT_COMMAND_UPLOAD) {
        /* Nonblocking open prevents a FIFO from hanging before regular-file validation. */
        source = open(o->local_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        struct stat st;
        if (source < 0 || fstat(source, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
            LOCAL("Unable to open a regular local source file.");
        if ((uintmax_t)st.st_size > UINT32_MAX) LOCAL("Local file exceeds the uint32 wire size limit.");
        size = (uint32_t)st.st_size;
    }
    if (o->command == CLIENT_COMMAND_DOWNLOAD) {
        path = strdup(o->local_path);
        if (path == NULL) LOCAL("Insufficient memory for destination path.");
        char *slash = strrchr(path, '/');
        const char *parent = ".";
        basename = path;
        if (slash != NULL) { *slash = 0; basename = slash + 1; parent = slash == path ? "/" : path; }
        if (basename[0] == 0 || strcmp(basename, ".") == 0 || strcmp(basename, "..") == 0)
            LOCAL("Invalid local destination filename.");
        directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) LOCAL("Unable to open destination directory.");
        struct stat st;
        if (fstatat(directory, basename, &st, AT_SYMLINK_NOFOLLOW) == 0)
            LOCAL("Local destination already exists; refusing to overwrite.");
        if (errno != ENOENT) LOCAL("Unable to inspect local destination.");
    }
    client_status_t initial_status;
    int rc = request_status(o, &o->deployment.primary, password, size, &c, &initial_status);
    if ((o->command == CLIENT_COMMAND_LIST || o->command == CLIENT_COMMAND_DOWNLOAD) && failover_eligible(rc)) {
        client_connection_close(c);
        c = NULL;
        replica_attempted = 1;
        fprintf(stderr, "Primary server unavailable; trying replica...\n");
        rc = request_status(o, &o->deployment.replica, password, size, &c, &initial_status);
    }
    WIRE(rc);
    if (initial_status != CLIENT_STATUS_OK) {
        result = (client_command_result_t){CLIENT_RESULT_STATUS, 0, initial_status, client_status_description(initial_status)};
        goto done;
    }
    /* No routing below this point: even OK followed by a truncated length/count
     * is final for this operation. Download staging starts only after status. */
    if (o->command == CLIENT_COMMAND_LIST) {
        uint32_t count;
        WIRE(client_protocol_read_u32(c, &count));
        if (count > CLIENT_LIST_MAX_ENTRIES) { result = wire_error(CLIENT_TRANSPORT_PROTOCOL_ERROR); goto done; }
        for (uint32_t i = 0; i < count; ++i) {
            char name[CLIENT_WIRE_FILENAME_MAX + 1];
            WIRE(client_protocol_read_filename(c, name));
            if (fprintf(output, "%s\n", name) < 0) LOCAL("Unable to write command output.");
        }
    } else if (o->command == CLIENT_COMMAND_UPLOAD) {
        unsigned char buffer[TRANSFER_CHUNK];
        uint32_t remaining = size;
        while (remaining != 0) {
            size_t want = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
            ssize_t n;
            do { n = read(source, buffer, want); } while (n < 0 && errno == EINTR);
            if (n <= 0) LOCAL("Unable to read the complete local file; upload was not confirmed.");
            WIRE(client_connection_write_all(c, buffer, (size_t)n));
            remaining -= (uint32_t)n;
        }
        STATUS();
    } else if (o->command == CLIENT_COMMAND_DOWNLOAD) {
        WIRE(client_protocol_read_u32(c, &size));
        /* Directory-relative operations keep staging and publication in the same
         * directory even if its path is renamed while the transfer is running. */
        unsigned char random[16];
        if (RAND_bytes(random, sizeof(random)) != 1) LOCAL("Unable to generate temporary filename.");
        memcpy(temporary, ".cs469-download-", 16);
        for (size_t i = 0; i < sizeof(random); ++i)
            (void)snprintf(temporary + 16 + i * 2, 3, "%02x", random[i]);
        target = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (target < 0) LOCAL("Unable to create temporary download file.");
        temp_exists = 1;
        unsigned char buffer[TRANSFER_CHUNK];
        uint32_t remaining = size;
        while (remaining != 0) {
            size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
            WIRE(client_connection_read_exact(c, buffer, chunk));
            size_t offset = 0;
            while (offset < chunk) {
                ssize_t n = write(target, buffer + offset, chunk - offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) LOCAL("Unable to write temporary download file.");
                offset += (size_t)n;
            }
            remaining -= (uint32_t)chunk;
        }
        if (fsync(target) < 0) LOCAL("Unable to sync downloaded file.");
        int closed = close(target);
        target = -1;
        if (closed < 0) LOCAL("Unable to close downloaded file.");
        /* POSIX rename overwrites. linkat atomically fails if basename exists,
         * including a symlink or a destination created during the transfer. */
        if (linkat(directory, temporary, directory, basename, 0) < 0)
            LOCAL(errno == EEXIST ? "Local destination already exists; refusing to overwrite." : "Unable to publish downloaded file.");
    }
    if (fflush(output) == EOF) LOCAL("Unable to write command output.");
done:
    client_connection_close(c);
    if (source >= 0 && close(source) < 0 && result.kind == CLIENT_RESULT_OK) result = local_error("Unable to close source file.");
    if (target >= 0) (void)close(target);
    if (temp_exists && unlinkat(directory, temporary, 0) < 0)
        result = local_error("Unable to remove temporary download file.");
    if (directory >= 0) (void)close(directory);
    free(path);
    if (replica_attempted && result.kind != CLIENT_RESULT_OK)
        fprintf(stderr, "Read could not be completed after trying the primary and replica.\n");
    return result;
#undef LOCAL
#undef WIRE
#undef STATUS
}
client_command_result_t client_execute(const client_options_t *options, char *password,
                                       size_t password_capacity, FILE *output) {
    client_command_result_t result;
    if (password == NULL || password_capacity == 0 || memchr(password, 0, password_capacity) == NULL)
        result = local_error("Invalid password buffer.");
    else result = execute(options, password, output);
    if (password != NULL) OPENSSL_cleanse(password, password_capacity);
    return result;
}
