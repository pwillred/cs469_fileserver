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

error_code_t handle_upload(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    uint32_t size;

    error_code_t err = read_and_verify_credentials(ssl, config, username);
    if (err != ERR_OK) {
        return err;
    }

    int ret = read_fully(ssl, &size, 4, config->timeout_sec);
    if (ret < 0) {
        return ERR_BAD_REQUEST;
    }
    size = ntohl(size);
    err = read_filename(ssl, config, filename);
    if (err != ERR_OK) return err;
    
    if (size > MAX_FILE_SIZE) {
        return ERR_TOO_LARGE;
    }
    
    char* user_dir = get_user_dir(username, config->data_dir);
    if (!user_dir) {
        return ERR_INTERNAL;
    }

    /* Two-phase UPLOAD: send preliminary OK before waiting for payload bytes.
     * The dispatch layer sends the final status; this is response 1. */
    if (send_error(ssl, ERR_OK) != 0) {
        free(user_dir);
        return ERR_INTERNAL;
    }

    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/.temp_%s", user_dir, filename);
    
    FILE* f = fopen(temp_path, "wb");
    if (!f) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    char* buf = malloc(8192);
    if (!buf) {
        fclose(f);
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    size_t remaining = size;
    while (remaining > 0) {
        size_t to_read = remaining < 8192 ? remaining : 8192;
        ret = read_fully(ssl, buf, to_read, config->timeout_sec);
        if (ret < 0) {
            free(buf);
            fclose(f);
            unlink(temp_path);
            free(user_dir);
            return ERR_BAD_REQUEST;
        }
        fwrite(buf, 1, to_read, f);
        remaining -= to_read;
    }
    
    fclose(f);
    free(buf);
    
    if (!config->peer_cert_path) {
        char final_path[512];
        snprintf(final_path, sizeof(final_path), "%s/%s", user_dir, filename);
        if (rename(temp_path, final_path) < 0) {
            free(user_dir);
            return ERR_INTERNAL;
        }
        free(user_dir);
        return ERR_OK;
    }
    
    SSL* replica_ssl = connect_to_replica(config);
    if (!replica_ssl) {
        unlink(temp_path);
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    error_code_t rep_status = send_upload_replication_header(replica_ssl, username, size, filename);
    if (rep_status != ERR_OK) {
        SSL_free(replica_ssl);
        close(SSL_get_fd(replica_ssl));
        unlink(temp_path);
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    rep_status = send_file_data(replica_ssl, temp_path, size);
    if (rep_status != ERR_OK) {
        SSL_free(replica_ssl);
        close(SSL_get_fd(replica_ssl));
        unlink(temp_path);
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    uint8_t replica_response;
    rep_status = read_replica_response(replica_ssl, &replica_response);
    if (rep_status != ERR_OK) {
        if (rep_status == ERR_EXISTS || rep_status == ERR_TOO_LARGE || rep_status == ERR_BAD_REQUEST) {
            SSL_free(replica_ssl);
            close(SSL_get_fd(replica_ssl));
            unlink(temp_path);
            free(user_dir);
            return rep_status;
        }
        SSL_free(replica_ssl);
        close(SSL_get_fd(replica_ssl));
        unlink(temp_path);
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    char final_path[512];
    snprintf(final_path, sizeof(final_path), "%s/%s", user_dir, filename);
    
    if (rename(temp_path, final_path) < 0) {
        uint8_t abort_byte = ABORT;
        send_commit_byte(replica_ssl, abort_byte);
        SSL_free(replica_ssl);
        close(SSL_get_fd(replica_ssl));
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    uint8_t commit_byte = COMMIT;
    if (send_commit_byte(replica_ssl, commit_byte) != 0) {
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    uint8_t confirm;
    rep_status = read_confirmation(replica_ssl, &confirm);
    SSL_free(replica_ssl);
    close(SSL_get_fd(replica_ssl));
    
    if (rep_status != ERR_OK || confirm != 0) {
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    free(user_dir);
    return ERR_OK;
}

error_code_t handle_delete(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    
    error_code_t err = read_and_verify_credentials(ssl, config, username);
    if (err != ERR_OK) {
        return err;
    }

    err = read_filename(ssl, config, filename);
    if (err != ERR_OK) {
    	return err;
    }
      
    char* user_dir = get_user_dir(username, config->data_dir);
    if (!user_dir) {
        return ERR_INTERNAL;
    }
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s", user_dir, filename);
    
    struct stat st;
    if (stat(file_path, &st) < 0 || !S_ISREG(st.st_mode)) {
        free(user_dir);
        return ERR_NOT_FOUND;
    }
    
    if (!config->peer_cert_path) {
        if (unlink(file_path) < 0) {
            free(user_dir);
            return ERR_INTERNAL;
        }
        free(user_dir);
        return ERR_OK;
    }
    
    SSL* replica_ssl = connect_to_replica(config);
    if (!replica_ssl) {
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    error_code_t rep_status = send_delete_replication_header(replica_ssl, username, filename);
    if (rep_status != ERR_OK) {
        SSL_free(replica_ssl);
        close(SSL_get_fd(replica_ssl));
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    uint8_t replica_response;
    rep_status = read_replica_response(replica_ssl, &replica_response);
    if (rep_status != ERR_OK) {
        SSL_free(replica_ssl);
        close(SSL_get_fd(replica_ssl));
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    if (unlink(file_path) < 0) {
        uint8_t abort_byte = ABORT;
        send_commit_byte(replica_ssl, abort_byte);
        SSL_free(replica_ssl);
        close(SSL_get_fd(replica_ssl));
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    uint8_t commit_byte = COMMIT;
    if (send_commit_byte(replica_ssl, commit_byte) != 0) {
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    uint8_t confirm;
    rep_status = read_confirmation(replica_ssl, &confirm);
    SSL_free(replica_ssl);
    close(SSL_get_fd(replica_ssl));
    
    if (rep_status != ERR_OK || confirm != 0) {
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    free(user_dir);
    return ERR_OK;
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
