#include "protocol.h"
#include "server.h"
#include "server_protocol_io.h"
#include "server_protocol_fields.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

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

/* connect_to_replica establishes an mTLS connection to the replica server.
 * Returns SSL* on success, NULL on failure. */
SSL* connect_to_replica(const server_config_t* config) {
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
    int sock = -1;
    
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL client context for replication: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    if (SSL_CTX_use_certificate_file(ctx, config->cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load client certificate for replication: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, config->key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load client private key for replication: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    if (SSL_CTX_load_verify_locations(ctx, config->peer_cert_path, NULL) <= 0) {
        fprintf(stderr, "Failed to load replica CA certificate: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket for replication: %s\n", strerror(errno));
        goto cleanup;
    }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->replication_port);
    
    if (inet_pton(AF_INET, config->coordinator_name, &addr.sin_addr) != 1) {
        struct hostent* he = gethostbyname(config->coordinator_name);
        if (!he) {
            fprintf(stderr, "Failed to resolve replica hostname %s\n", config->coordinator_name);
            goto cleanup;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to replica %s:%d: %s\n",
                config->coordinator_name, config->replication_port, strerror(errno));
        goto cleanup;
    }
    
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object for replication: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    if (SSL_set_fd(ssl, sock) != 1) {
        fprintf(stderr, "Failed to set SSL file descriptor: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "Failed to complete SSL handshake with replica: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    SSL_CTX_free(ctx);
    return ssl;
    
cleanup:
    if (ssl) SSL_free(ssl);
    if (sock >= 0) close(sock);
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}

/* SSL_set_fd installs a non-owning socket BIO. A successful connect transfers
 * both SSL and fd to the caller; destroy SSL before closing the saved fd. */
void close_replica_connection(SSL *ssl) {
    if (!ssl) return;
    int fd = SSL_get_fd(ssl);
    SSL_free(ssl);
    if (fd >= 0) close(fd);
}

/* send_upload_replication_header sends the upload replication header to a replica.
 * Returns ERR_OK on success, error code on failure. */
error_code_t send_upload_replication_header(SSL* ssl, const char* username, 
                                            uint32_t file_size, const char* filename) {
    const uint8_t cmd[] = "UPLOAD";
    uint32_t be_size = htonl(file_size);
    
    if (write_fully(ssl, cmd, UPLOAD_CMD_LEN) != 0) return ERR_BAD_REQUEST;
    if (write_fully(ssl, username, strlen(username) + 1) != 0) return ERR_BAD_REQUEST;
    if (write_fully(ssl, &be_size, 4) != 0) return ERR_BAD_REQUEST;
    if (write_fully(ssl, filename, strlen(filename) + 1) != 0) return ERR_BAD_REQUEST;
    
    return ERR_OK;
}

/* send_delete_replication_header sends the delete replication header to a replica.
 * Returns ERR_OK on success, error code on failure. */
error_code_t send_delete_replication_header(SSL* ssl, const char* username, const char* filename) {
    const uint8_t cmd[] = "DELETE";
    
    if (write_fully(ssl, cmd, DELETE_CMD_LEN) != 0) return ERR_BAD_REQUEST;
    if (write_fully(ssl, username, strlen(username) + 1) != 0) return ERR_BAD_REQUEST;
    if (write_fully(ssl, filename, strlen(filename) + 1) != 0) return ERR_BAD_REQUEST;
    
    return ERR_OK;
}

/* send_file_data sends file data from a temp file over SSL.
 * Returns ERR_OK on success, error code on failure. */
error_code_t send_file_data(SSL* ssl, const char* temp_path, uint32_t file_size) {
    FILE* f = fopen(temp_path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open temp file for replication: %s\n", temp_path);
        return ERR_INTERNAL;
    }
    
    uint8_t buffer[16384];
    size_t remaining = file_size;
    
    while (remaining > 0) {
        size_t to_read = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        size_t n = fread(buffer, 1, to_read, f);
        if (n != to_read) {
            fprintf(stderr, "Failed to read temp file for replication\n");
            fclose(f);
            return ERR_BAD_REQUEST;
        }
        if (write_fully(ssl, buffer, n) != 0) {
            fclose(f);
            return ERR_BAD_REQUEST;
        }
        remaining -= n;
    }
    
    fclose(f);
    return ERR_OK;
}

/* read_replica_response reads a 1-byte response from a replica.
 * Returns ERR_OK with *response=0 for prepare/ready, or error code otherwise. */
error_code_t read_replica_response(SSL* ssl, uint8_t* response) {
    if (read_fully(ssl, response, 1, DEFAULT_TIMEOUT) != 0) {
        return ERR_REPLICATION_FAILED;
    }
    
    if (*response == 0) {
        return ERR_OK;
    }
    
    if (*response <= 7) {
        return (error_code_t)*response;
    }
    
    return ERR_INTERNAL;
}

/* send_commit_byte sends a commit or abort byte to a replica.
 * Returns 0 on success, -1 on failure. */
int send_commit_byte(SSL* ssl, uint8_t commit_byte) {
    return write_fully(ssl, &commit_byte, 1);
}

/* read_confirmation reads a 1-byte confirmation from a replica.
 * Returns ERR_OK on success, error code on failure. */
error_code_t read_confirmation(SSL* ssl, uint8_t* confirm) {
    if (read_fully(ssl, confirm, 1, DEFAULT_TIMEOUT) != 0) {
        return ERR_REPLICATION_FAILED;
    }
    return ERR_OK;
}
