/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * server_replication.c provides the replica-side replication endpoint for accepting
 * mTLS connections from the primary server and handling replication protocol.
 */

#include "server_replication.h"
#include "protocol.h"
#include "server_auth.h"
#include "server.h"
#include "server_protocol_fields.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* capacity includes the framing NUL; protocol maxima count content only. */
static int read_null_terminated(SSL* ssl, char* buf, size_t capacity) {
    size_t i = 0;
    while (i < capacity) {
        ssize_t n = SSL_read(ssl, &buf[i], 1);
        if (n <= 0) return -1;
        if (buf[i] == '\0') return 0;
        i++;
    }
    return -1;
}

static int read_uint32_be(SSL* ssl, uint32_t* out) {
    uint8_t bytes[4];
    if (SSL_read(ssl, bytes, 4) != 4) return -1;
    *out = (uint32_t)(bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    return 0;
}

error_code_t handle_upload_replica(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1] = {0};
    char filename[MAX_FILENAME_LEN + 1] = {0};
    uint32_t file_size = 0;
    char temp_path[512] = {0};
    
    if (read_null_terminated(ssl, username, sizeof(username)) != 0) return ERR_BAD_REQUEST;
    if (read_uint32_be(ssl, &file_size) != 0) return ERR_BAD_REQUEST;
    if (read_null_terminated(ssl, filename, sizeof(filename)) != 0) return ERR_BAD_REQUEST;
    
    if (!validate_filename(filename)) return ERR_BAD_REQUEST;
    if (file_size > MAX_FILE_SIZE) return ERR_TOO_LARGE;
    
    char* user_dir = get_user_dir(username, config->data_dir);
    if (!user_dir) return ERR_INTERNAL;
    
    if (filename_fits_directory(user_dir, filename) != 0) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    char final_path[512];
    int length = snprintf(final_path, sizeof(final_path), "%s/%s", user_dir, filename);
    if (length < 0 || (size_t)length >= sizeof(final_path)) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    struct stat st;
    if (stat(final_path, &st) == 0 && S_ISREG(st.st_mode)) {
        free(user_dir);
        return ERR_EXISTS;
    }
    length = snprintf(temp_path, sizeof(temp_path), "%s/.temp_XXXXXX", user_dir);
    if (length < 0 || (size_t)length >= sizeof(temp_path)) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    /* Exclusive creation, mode 0600, independent of destination component length. */
    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        close(fd);
        unlink(temp_path);
        free(user_dir);
        return ERR_INTERNAL;
    }

    size_t remaining = file_size;
    uint8_t buffer[16384];
    while (remaining > 0) {
        size_t to_read = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        ssize_t n = SSL_read(ssl, buffer, to_read);
        if (n <= 0) {
            close(fd);
            unlink(temp_path);
            free(user_dir);
            return ERR_BAD_REQUEST;
        }
        size_t offset = 0;
        while (offset < (size_t)n) {
            ssize_t written = write(fd, buffer + offset, (size_t)n - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) {
                close(fd);
                unlink(temp_path);
                free(user_dir);
                return ERR_INTERNAL;
            }
            offset += (size_t)written;
        }
        remaining -= (size_t)n;
    }
    
    if (close(fd) < 0) {
        unlink(temp_path);
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    uint8_t prepare_ok = PREPARE_OK;
    if (SSL_write(ssl, &prepare_ok, 1) != 1) {
        unlink(temp_path);
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    uint8_t commit_byte;
    if (SSL_read(ssl, &commit_byte, 1) != 1) {
        unlink(temp_path);
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    error_code_t result = ERR_OK;
    if (commit_byte == COMMIT) {
        if (rename(temp_path, final_path) < 0) {
            result = ERR_INTERNAL;
            unlink(temp_path);
        }
        uint8_t confirm = result == ERR_OK ? 0 : 1;
        if (SSL_write(ssl, &confirm, 1) != 1) result = ERR_REPLICATION_FAILED;
    } else {
        unlink(temp_path);
        uint8_t confirm = 0;
        (void)SSL_write(ssl, &confirm, 1);
    }
    
    free(user_dir);
    return result;
}

error_code_t handle_delete_replica(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1] = {0};
    char filename[MAX_FILENAME_LEN + 1] = {0};
    
    if (read_null_terminated(ssl, username, sizeof(username)) != 0) return ERR_BAD_REQUEST;
    if (read_null_terminated(ssl, filename, sizeof(filename)) != 0) return ERR_BAD_REQUEST;
    
    if (!validate_filename(filename)) return ERR_BAD_REQUEST;
    
    char* user_dir = get_user_dir(username, config->data_dir);
    if (!user_dir) return ERR_INTERNAL;
    
    /* An unrepresentable component cannot identify an existing file. */
    if (filename_fits_directory(user_dir, filename) != 0) {
        free(user_dir);
        return ERR_NOT_FOUND;
    }
    char file_path[512];
    int length = snprintf(file_path, sizeof(file_path), "%s/%s", user_dir, filename);
    if (length < 0 || (size_t)length >= sizeof(file_path)) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    struct stat st;
    if (stat(file_path, &st) < 0 || !S_ISREG(st.st_mode)) {
        free(user_dir);
        uint8_t not_found = ERR_NOT_FOUND;
        (void)SSL_write(ssl, &not_found, 1);
        return ERR_NOT_FOUND;
    }
    
    uint8_t ready = PREPARE_OK;
    if (SSL_write(ssl, &ready, 1) != 1) {
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    uint8_t commit_byte;
    if (SSL_read(ssl, &commit_byte, 1) != 1) {
        free(user_dir);
        return ERR_REPLICATION_FAILED;
    }
    
    error_code_t result = ERR_OK;
    if (commit_byte == COMMIT) {
        if (unlink(file_path) < 0) {
            result = ERR_INTERNAL;
        }
        uint8_t confirm = result == ERR_OK ? 0 : 1;
        if (SSL_write(ssl, &confirm, 1) != 1) result = ERR_REPLICATION_FAILED;
    } else {
        uint8_t confirm = 0;
        (void)SSL_write(ssl, &confirm, 1);
    }
    
    free(user_dir);
    return result;
}

static void* do_replication_handler(SSL *ssl, const server_config_t *config ) {
    uint8_t cmd_buf[8];
    ssize_t n = SSL_read(ssl, cmd_buf, 6);
    if (n != 6) {
        fprintf(stderr, "Failed to read replication command\n");
    } else {
        cmd_buf[n] = '\0';
        error_code_t status = ERR_INTERNAL;
            
        if (strcmp((char*)cmd_buf, UPLOAD_CMD) == 0) {
            status = handle_upload_replica(ssl, config);
        } else if (strcmp((char*)cmd_buf, DELETE_CMD) == 0) {
            status = handle_delete_replica(ssl, config);
        } else {
            fprintf(stderr, "Unknown replication command: %s\n", cmd_buf);
            status = ERR_BAD_REQUEST;
        }
            
        if (status != ERR_OK) {
            uint8_t err_byte = server_status_byte(status);
            if (SSL_write(ssl, &err_byte, 1) != 1) {
                fprintf(stderr, "Failed to send error response\n");
            }
        }
    }
    return NULL;
}

SSL_CTX* init_replication_ssl(const server_config_t* config) {
    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context for replication\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, config->cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate for replication\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config->key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key for replication\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_load_verify_locations(ctx, config->peer_cert_path, NULL) <= 0) {
        fprintf(stderr, "Failed to load peer cert verify locations\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    return ctx;
}

void* replication_handler(void* arg) {
    client_context_t *ctx = arg;
    SSL *ssl = SSL_new(ctx->ssl_ctx);
    struct timeval timeout = {ctx->config->timeout_sec, 0};
    if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ||
        !ssl || SSL_set_fd(ssl, ctx->sock) != 1 || SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Failed to establish TLS connection\n");
    } else {
        do_replication_handler(ssl, ctx->config);
    }
    SSL_free(ssl);
    release_client_context(ctx);
    return NULL;
}

