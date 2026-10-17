/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * server_replication.h provides declarations for the replica-side replication endpoint.
 */

#ifndef SERVER_REPLICATION_H
#define SERVER_REPLICATION_H

#include <openssl/ssl.h>
#include "protocol.h"
#include "server_read_ops.h"
#include "server.h"

SSL_CTX* init_replication_ssl(const server_config_t* config);
void* replication_handler(void* arg);

error_code_t handle_upload_replica(SSL* ssl, const server_config_t* config);
error_code_t handle_delete_replica(SSL* ssl, const server_config_t* config);

#endif /* SERVER_REPLICATION_H */
