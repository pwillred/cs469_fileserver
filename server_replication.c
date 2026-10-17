/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * server_replication.c provides the replica-side replication endpoint for accepting
 * mTLS connections from the primary server and handling replication protocol.
 */

#include "server_replication.h"
#include "protocol.h"
#include <openssl/err.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    SSL_CTX* ssl_ctx;
    int sock;
    const server_config_t* config;
} replication_context_t;

static void release_replication_context(replication_context_t* ctx) {
    SSL_CTX_free(ctx->ssl_ctx);
    close(ctx->sock);
    free((void*)ctx->config->data_dir);
    free((void*)ctx->config->auth_db_path);
    free(ctx->config);
    free(ctx);
}

server_read_result_t replication_handle_upload(SSL* ssl, const server_config_t* config);

static void* do_replication_handler(void* arg) {
    replication_context_t* ctx = (replication_context_t*)arg;
    SSL* ssl = SSL_new(ctx->ssl_ctx);

    struct timeval timeout = {ctx->config->timeout_sec, 0};
    if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ||
        !ssl || SSL_set_fd(ssl, ctx->sock) != 1 || SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Failed to establish TLS connection for replication\n");
    } else {
        server_read_result_t result = replication_handle_upload(ssl, ctx->config);
        if (result.complete) {
            (void)SSL_shutdown(ssl);
        } else {
            fprintf(stderr, "Replication request ended with incomplete response\n");
            (void)shutdown(ctx->sock, SHUT_RDWR);
        }
    }

    SSL_free(ssl);
    release_replication_context(ctx);
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
    int sock = *(int*)arg;
    server_config_t* config = *(server_config_t**)((char*)arg + sizeof(int));
    free(arg);

    server_config_t* config_copy = malloc(sizeof(server_config_t));
    if (!config_copy) {
        close(sock);
        return NULL;
    }

    *config_copy = *config;
    config_copy->cert_path = strdup(config_copy->cert_path);
    config_copy->key_path = strdup(config_copy->key_path);
    config_copy->data_dir = strdup(config_copy->data_dir);
    config_copy->auth_db_path = strdup(config_copy->auth_db_path);
    config_copy->coordinator_name = strdup(config_copy->coordinator_name);
    config_copy->peer_cert_path = strdup(config_copy->peer_cert_path);

    if (!config_copy->data_dir || !config_copy->auth_db_path) {
        free(config_copy->data_dir);
        free(config_copy->auth_db_path);
        free(config_copy);
        close(sock);
        return NULL;
    }

    SSL_CTX* ssl_ctx = init_replication_ssl(config_copy);
    if (!ssl_ctx) {
        free(config_copy->data_dir);
        free(config_copy->auth_db_path);
        free(config_copy);
        close(sock);
        return NULL;
    }

    replication_context_t* ctx = malloc(sizeof(replication_context_t));
    if (!ctx) {
        SSL_CTX_free(ssl_ctx);
        free((void*)config_copy->cert_path);
        free((void*)config_copy->key_path);
        free((void*)config_copy->data_dir);
        free((void*)config_copy->auth_db_path);
        free((void*)config_copy->coordinator_name);
        free((void*)config_copy->peer_cert_path);
        free(config_copy);
        return NULL;
    }

    ctx->ssl_ctx = ssl_ctx;
    ctx->sock = sock;
    ctx->config = config_copy;

    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&thread, &attr, do_replication_handler, ctx) != 0) {
        SSL_CTX_free(ssl_ctx);
        release_replication_context(ctx);
        return NULL;
    }

    pthread_attr_destroy(&attr);
    return NULL;
}

server_read_result_t replication_handle_upload(SSL* ssl, const server_config_t* config) {
    (void)ssl;
    (void)config;

    uint8_t prepare_response = 7;
    if (write_fully(ssl, &prepare_response, 1) != 0) {
        return (server_read_result_t){.status = ERR_INTERNAL, .complete = 0};
    }

    return (server_read_result_t){.status = ERR_INTERNAL, .complete = 1};
}
