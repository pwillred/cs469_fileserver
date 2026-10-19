#include "server_auth.h"
#include "server_protocol_io.h"
#include "server_protocol_fields.h"
#include <openssl/crypto.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "protocol.h"
#include "server.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

void release_client_context(client_context_t *ctx) {
    SSL_CTX_free(ctx->ssl_ctx);
    close(ctx->sock);
    free(ctx);
}

void* handle_client(void* arg) {
    client_context_t *ctx = arg;
    SSL *ssl = SSL_new(ctx->ssl_ctx);
    struct timeval timeout = {ctx->config->timeout_sec, 0};
    if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ||
        !ssl || SSL_set_fd(ssl, ctx->sock) != 1 || SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Failed to establish TLS connection\n");
    } else {
       server_read_result_t result = handle_request(ssl, ctx->config);
       if (result.complete) (void)SSL_shutdown(ssl);
        else {
            fprintf(stderr, "Request ended with incomplete response\n");
            (void)shutdown(ctx->sock, SHUT_RDWR);
        }
    }
    SSL_free(ssl);
    release_client_context(ctx);
    return NULL;
}

static error_code_t reject_replica_write(const server_read_io_t *io, int upload) {
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1] = {0};
    char filename[MAX_FILENAME_LEN + 1];
    uint32_t size = 0;
    int drained = server_read_field(io, username, sizeof(username)) != 0 &&
                  server_read_field(io, password, sizeof(password)) != 0;
    if (drained && upload)
        drained = io->read_exact(io->state, &size, sizeof(size)) == 0;
    if (drained)
        drained = server_read_field(io, filename, sizeof(filename)) != 0;
    OPENSSL_cleanse(password, sizeof(password));
    (void)size;
    return drained ? ERR_REPLICATION_FAILED : ERR_BAD_REQUEST;
}

server_read_result_t handle_request(SSL* ssl, const server_config_t* config) {
    server_protocol_io_t state;
    server_read_io_t io;
    if (server_protocol_io_init(&state, ssl, config->timeout_sec * 1000, &io) != 0)
        return (server_read_result_t){ERR_INTERNAL, 0};
    const char *verbs[] = {LIST_CMD, UPLOAD_CMD, DOWNLOAD_CMD, DELETE_CMD};
    char command[DOWNLOAD_CMD_LEN];
    int selected = -1;
    for (size_t n = 1; n <= sizeof(command); ++n) {
        if (io.read_exact(io.state, command + n - 1, 1) != 0) break;
        int possible = 0;
        for (int i = 0; i < 4; ++i) {
            size_t length = strlen(verbs[i]);
            if (n <= length && memcmp(command, verbs[i], n) == 0) {
                possible = 1;
                if (n == length) selected = i;
            }
        }
        if (selected >= 0 || !possible) break;
    }
    server_read_context_t read_context = {config->data_dir, config->auth_db_path};
    if (selected == 0) return server_handle_list(&io, &read_context);
    if (selected == 2) return server_handle_download(&io, &read_context);
    error_code_t status = ERR_BAD_REQUEST;
    if (selected == 1) {
        if (config->role == ROLE_REPLICA) {
            status = reject_replica_write(&io, 1);
        } else {
            status = handle_upload(ssl, config);
        }
    }
    if (selected == 3) {
        if (config->role == ROLE_REPLICA) {
            status = reject_replica_write(&io, 0);
        } else {
            status = handle_delete(ssl, config);
        }
    }
    int sent = selected == 1 || selected == 3 ? send_error(ssl, status) : server_write_status(&io, status);
    if (sent != 0) { io.abort(io.state); return (server_read_result_t){ERR_INTERNAL, 0}; }
    return (server_read_result_t){status, 1};
}

/* Only active primary writes occupy this registry. Entries and their keys live
 * in the owning handler's stack until release. Waiters recheck after broadcasts;
 * unrelated keys never wait for network/disk work under the registry mutex.
 * Workers are not canceled by shutdown. Defer cancellation while registered so
 * every exit first closes resources and removes its stack entry. */
typedef struct write_guard {
    const char *user;
    const char *name;
    struct write_guard *next;
    int cancellation_state;
} write_guard_t;
static pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t write_changed = PTHREAD_COND_INITIALIZER;
static write_guard_t *active_writes;

static int acquire_write(write_guard_t *guard, const char *user, const char *name) {
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &guard->cancellation_state) != 0)
        return -1;
    if (pthread_mutex_lock(&write_mutex) != 0) {
        pthread_setcancelstate(guard->cancellation_state, NULL);
        return -1;
    }
    for (;;) {
        write_guard_t *entry = active_writes;
        while (entry && (strcmp(entry->user, user) || strcmp(entry->name, name)))
            entry = entry->next;
        if (!entry) break;
        if (pthread_cond_wait(&write_changed, &write_mutex) != 0) {
            pthread_mutex_unlock(&write_mutex);
            pthread_setcancelstate(guard->cancellation_state, NULL);
            return -1;
        }
    }
    guard->user = user;
    guard->name = name;
    guard->next = active_writes;
    active_writes = guard;
    pthread_mutex_unlock(&write_mutex);
    return 0;
}

static void release_write(write_guard_t *guard) {
    pthread_mutex_lock(&write_mutex);
    write_guard_t **entry = &active_writes;
    while (*entry != guard) entry = &(*entry)->next;
    *entry = guard->next;
    pthread_cond_broadcast(&write_changed);
    pthread_mutex_unlock(&write_mutex);
    pthread_setcancelstate(guard->cancellation_state, NULL);
}

error_code_t handle_upload(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    uint32_t size;
    error_code_t err = read_and_verify_credentials(ssl, config, username);
    if (err != ERR_OK) return err;
    if (read_fully(ssl, &size, 4, config->timeout_sec) < 0) return ERR_BAD_REQUEST;
    size = ntohl(size);
    err = read_filename(ssl, config, filename);
    if (err != ERR_OK) return err;
    if (size > MAX_FILE_SIZE) return ERR_TOO_LARGE;

    write_guard_t guard;
    if (acquire_write(&guard, username, filename) != 0) return ERR_INTERNAL;
    char *user_dir = get_user_dir(username, config->data_dir);
    char temp_path[512], final_path[512];
    int staged = 0;
    FILE *file = NULL;
    SSL *peer = NULL;
    err = ERR_INTERNAL;
    if (!user_dir) goto done;
    int length = snprintf(temp_path, sizeof(temp_path), "%s/.temp_XXXXXX", user_dir);
    if (length < 0 || (size_t)length >= sizeof(temp_path)) goto done;
    length = snprintf(final_path, sizeof(final_path), "%s/%s", user_dir, filename);
    if (length < 0 || (size_t)length >= sizeof(final_path)) goto done;

    /* Response 1 precedes payload. Dispatch owns response 2. */
    if (send_error(ssl, ERR_OK) != 0) goto done;
    int fd = mkstemp(temp_path); /* exclusive, unique, mode 0600 */
    if (fd < 0) goto done;
    staged = 1;
    file = fdopen(fd, "wb");
    if (!file) { close(fd); goto done; }
    unsigned char buffer[8192];
    size_t remaining = size;
    while (remaining) {
        size_t count = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        if (read_fully(ssl, buffer, count, config->timeout_sec) < 0) {
            err = ERR_BAD_REQUEST;
            goto done;
        }
        size_t offset = 0;
        while (offset < count) {
            size_t written = fwrite(buffer + offset, 1, count - offset, file);
            if (ferror(file) || written == 0) goto done;
            offset += written;
        }
        remaining -= count;
    }
    int closed = fclose(file);
    file = NULL; /* fclose consumes the stream even on failure. */
    if (closed != 0) goto done;

    err = ERR_REPLICATION_FAILED;
    peer = connect_to_replica(config);
    if (!peer) goto done;
    if (send_upload_replication_header(peer, username, size, filename) != ERR_OK ||
        send_file_data(peer, temp_path, size) != ERR_OK) goto done;
    uint8_t response;
    error_code_t prepared = read_replica_response(peer, &response);
    if (prepared != ERR_OK) {
        if (prepared == ERR_EXISTS || prepared == ERR_TOO_LARGE || prepared == ERR_BAD_REQUEST)
            err = prepared;
        goto done;
    }
    if (rename(temp_path, final_path) < 0) {
        (void)send_commit_byte(peer, ABORT);
        err = ERR_INTERNAL;
        goto done;
    }
    staged = 0;
    if (send_commit_byte(peer, COMMIT) != 0) goto done;
    uint8_t confirm;
    if (read_confirmation(peer, &confirm) != ERR_OK || confirm != 0) goto done;
    err = ERR_OK;
done:
    if (file) (void)fclose(file);
    close_replica_connection(peer);
    if (staged) (void)unlink(temp_path);
    free(user_dir);
    release_write(&guard);
    return err;
}

error_code_t handle_delete(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    error_code_t err = read_and_verify_credentials(ssl, config, username);
    if (err != ERR_OK) return err;
    err = read_filename(ssl, config, filename);
    if (err != ERR_OK) return err;

    write_guard_t guard;
    if (acquire_write(&guard, username, filename) != 0) return ERR_INTERNAL;
    char *user_dir = get_user_dir(username, config->data_dir);
    SSL *peer = NULL;
    char file_path[512];
    err = ERR_INTERNAL;
    if (!user_dir) goto done;
    int length = snprintf(file_path, sizeof(file_path), "%s/%s", user_dir, filename);
    if (length < 0 || (size_t)length >= sizeof(file_path)) goto done;
    struct stat st;
    if (stat(file_path, &st) < 0 || !S_ISREG(st.st_mode)) {
        err = ERR_NOT_FOUND;
        goto done;
    }
    err = ERR_REPLICATION_FAILED;
    peer = connect_to_replica(config);
    if (!peer || send_delete_replication_header(peer, username, filename) != ERR_OK)
        goto done;
    uint8_t response;
    if (read_replica_response(peer, &response) != ERR_OK) goto done;
    if (unlink(file_path) < 0) {
        (void)send_commit_byte(peer, ABORT);
        err = ERR_INTERNAL;
        goto done;
    }
    if (send_commit_byte(peer, COMMIT) != 0) goto done;
    uint8_t confirm;
    if (read_confirmation(peer, &confirm) != ERR_OK || confirm != 0) goto done;
    err = ERR_OK;
done:
    close_replica_connection(peer);
    free(user_dir);
    release_write(&guard);
    return err;
}

error_code_t read_and_verify_credentials(SSL* ssl, const server_config_t* config, char *username) {
    char password[MAX_PASSWORD_LEN + 1] = {0};
    error_code_t status = ERR_BAD_REQUEST;
    server_protocol_io_t state;
    server_read_io_t io;
    if (server_protocol_io_init(&state, ssl, config->timeout_sec * 1000, &io) != 0) {
        status = ERR_INTERNAL;
    } else {
        size_t u = server_read_field(&io, username, MAX_USERNAME_LEN + 1);
        size_t p = u ? server_read_field(&io, password, sizeof(password)) : 0;
        if (u && p) status = server_auth_to_error(server_auth_verify(
            config->auth_db_path, username, u, password, p));
    }
    OPENSSL_cleanse(password, sizeof(password));
    return status;
}

error_code_t read_filename(SSL *ssl, const server_config_t *config, char *filename) {
    server_protocol_io_t state;
    server_read_io_t io;
    if (!filename) return ERR_BAD_REQUEST;
    if (server_protocol_io_init(&state, ssl, config->timeout_sec * 1000, &io) != 0) return ERR_INTERNAL;
    if (!server_read_field(&io, filename, MAX_FILENAME_LEN + 1) || !validate_filename(filename))
        return ERR_BAD_REQUEST;
    return ERR_OK;
}
