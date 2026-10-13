#include "server_auth.h"
#include "server_protocol_io.h"
#include "server_protocol_fields.h"
#include <openssl/crypto.h>
#include <sys/time.h>
#include <sys/socket.h>
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

/* Also used when thread creation fails; only owned worker resources live here. */
void release_client_context(client_context_t *ctx) {
    SSL_CTX_free(ctx->ssl_ctx);
    close(ctx->sock);
    free((void *)ctx->config_storage.cert_path);
    free((void *)ctx->config_storage.key_path);
    free((void *)ctx->config_storage.data_dir);
    free((void *)ctx->config_storage.auth_db_path);
    free(ctx);
}

/* handle_client is a function that can be passed into pthread_create.  It sets up the SSL connection
 * for the incoming request, and dispatches the request to the appropriate handle, cleaning up system
 * resources once work is done. */ 
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

/* Known verbs are prefix-free. Stop at the first exact match; never read the
 * first username byte. A nonmatching prefix fails immediately. */
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
    if (selected == 1) status = handle_upload(ssl, config);
    if (selected == 3) status = handle_delete(ssl, config);
    /* Legacy writes retain one final status, never a fabricated preliminary OK.
     * Their helpers retain per-call timeouts, so don't reuse the command deadline. */
    int sent = selected == 1 || selected == 3 ? send_error(ssl, status) : server_write_status(&io, status);
    if (sent != 0) { io.abort(io.state); return (server_read_result_t){ERR_INTERNAL, 0}; }
    return (server_read_result_t){status, 1};
}

/* handle_upload handles the UPLOAD commands for an open connection. */
error_code_t handle_upload(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    uint32_t size;

    /* Check password... */
    error_code_t err = read_and_verify_credentials(ssl, config, username);
    if (err != ERR_OK) {
        return err;
    }

    /* Frozen request header: size before the NUL-terminated filename.
     * Payload/replication/response semantics below remain partner-owned. */
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
    
    /* Find the user's directory, the build the new filename. */
    char* user_dir = get_user_dir(username, config->data_dir);
    if (!user_dir) {
        return ERR_INTERNAL;
    }
    
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/.temp_%s", user_dir, filename);
    
    /* open the file to upload. */
    FILE* f = fopen(temp_path, "wb");
    if (!f) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    /* Allocate an 8Kb buffer on the heap for the upload. */
    char* buf = malloc(8192);
    if (!buf) {
        fclose(f);
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    /* Read the file, one buffer at a time. */
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
	/* Write data out to the file. */
        fwrite(buf, 1, to_read, f);
        remaining -= to_read;
    }
    
    fclose(f);
    free(buf);
    
    char final_path[512];
    snprintf(final_path, sizeof(final_path), "%s/%s", user_dir, filename);
    
    /* TODO prepare/commit flow goes here.  This is stubbed out. */
    if (rename(temp_path, final_path) < 0) {
        unlink(temp_path);
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    free(user_dir);
    return ERR_OK;
}

/* handle_delete processes the DELETE command, removing a file from a user's home directory. */
error_code_t handle_delete(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    
    /* verify the usernmae and password, then the filename. */
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
    
    if (unlink(file_path) < 0) {
        free(user_dir);
        return ERR_NOT_FOUND;
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
