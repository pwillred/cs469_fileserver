/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * server.h provides declarations used for implementing the fileserver, excluding replicaiton and password work.
 */

#ifndef SERVER_H
#define SERVER_H

#define DEFAULT_TIMEOUT 15

#include "protocol.h"

#include <openssl/ssl.h>

/* Server configuration */
typedef struct {
    int port;
    const char* cert_path;
    const char* key_path;
    const char* data_dir;
    int timeout_sec;
} server_config_t;

/* Client context passed to handler thread */
typedef struct {
    SSL_CTX* ssl_ctx;
    int sock;
    const server_config_t* config;
} client_context_t;

/* Function prototypes */
server_config_t* parse_args(int argc, const char** argv);
SSL_CTX* init_ssl(const server_config_t* config);
int setup_tcp_socket(const server_config_t* config);
void* handle_client(void* arg);
error_code_t handle_request(SSL* ssl, const server_config_t* config);
error_code_t handle_upload(SSL* ssl, const server_config_t* config);
error_code_t handle_delete(SSL* ssl, const server_config_t* config);
void shutdown_server(int sig);

int read_fully(SSL* ssl, void* buf, size_t len, int timeout_sec);
int write_fully(SSL* ssl, const void* buf, size_t len);
int send_error(SSL* ssl, error_code_t err);
int validate_filename(const char* filename);
char* get_user_dir(const char* username, const char* data_dir);
error_code_t read_and_verify_credentials(SSL* ssl, const server_config_t* config, char *username);
error_code_t read_filename(SSL *ssl, const server_config_t *config, char *filename);

#endif /* SERVER_H */
