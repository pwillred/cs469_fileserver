/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * server.h provides declarations used for implementing the fileserver, excluding replicaiton and password work.
 */

#ifndef SERVER_H
#define SERVER_H

#define DEFAULT_TIMEOUT 15
#define DEFAULT_REPLICATION_PORT 8081

#include "protocol.h"
#include "server_read_ops.h"

#include <openssl/ssl.h>

/* Server role enum */
typedef enum {
    ROLE_PRIMARY,
    ROLE_REPLICA
} server_role_t;

/* Server configuration */
typedef struct {
    int port;
    const char* cert_path;
    const char* key_path;
    const char* data_dir;
    const char* auth_db_path;
    int timeout_sec;
    server_role_t role;
    int replication_port;
    const char* coordinator_name;
    const char* peer_cert_path;
} server_config_t;

/* Client context passed to handler thread */
typedef struct {
    SSL_CTX* ssl_ctx;
    int sock;
    const server_config_t* config;
    server_config_t config_storage; /* worker-owned copy, including data/auth paths */
} client_context_t;

/* Function prototypes */
server_config_t* parse_args(int argc, const char** argv);
SSL_CTX* init_ssl(const server_config_t* config);
SSL_CTX* init_replication_ssl(const server_config_t* config);
void* replication_handler(void* arg);
int setup_tcp_socket(int port);
void* handle_client(void* arg);
void release_client_context(client_context_t *ctx);
/* Owns the entire response, including legacy write final status. */
server_read_result_t handle_request(SSL* ssl, const server_config_t* config);
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

SSL* connect_to_replica(const server_config_t* config);
error_code_t send_upload_replication_header(SSL* ssl, const char* username, 
                                            uint32_t file_size, const char* filename);
error_code_t send_delete_replication_header(SSL* ssl, const char* username, const char* filename);
error_code_t send_file_data(SSL* ssl, const char* temp_path, uint32_t file_size);
error_code_t read_replica_response(SSL* ssl, uint8_t* response);
int send_commit_byte(SSL* ssl, uint8_t commit_byte);
error_code_t read_confirmation(SSL* ssl, uint8_t* confirm);

#endif /* SERVER_H */
