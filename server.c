/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * server.c provides the main function and handler threads for the server side of the fileserver.
 */

#include "protocol.h"
#include "server.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Global flag to indicate a shutdown of the server was requested. */
static volatile sig_atomic_t keep_running = 1;
/* The socket used for listening for connections. */
static int listen_socket = 0;

/**
 * parse_args takes in the command line arguments passed to the server, generates a 
 * server_config_t from them, and returns it to the caller.  On invalid arguments, NULL
 * is returned instead.
 *
 * Memory for the server_config_t should be free()'d by the caller.
 */
server_config_t* parse_args(int argc, const char** argv) {
    server_config_t* config = calloc(1, sizeof(server_config_t));
    if (!config) {
        fprintf(stderr, "Failed to allocate config\n");
        return NULL;
    }
   
    config->timeout_sec = DEFAULT_TIMEOUT;
   
    /* Iterate over the arguments, finding recognized values and terminating early if any aren't understood. */ 
    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            config->port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config->cert_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            config->key_path = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            config->data_dir = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            config->timeout_sec = atoi(argv[++i]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            free(config);
            return NULL;
        }
    }
    
    /* Ensure the configuration makes logical sense.  */
    if (config->port == 0 || !config->cert_path || !config->key_path || !config->data_dir) {
        fprintf(stderr, "Usage: %s -p port -c cert -k key -d data_dir [--timeout seconds]\n", argv[0]);
        free(config);
        return NULL;
    }
    
    
    return config;
}


/**
 * init_ssl prepares the openssl library to receive and handle SSL connections.  It takes the server config
 * as an argument, and returns a SSL_CTX* for use.  Callers are responsible for free-ing the SSL_CTX.  NULL is
 * returned if any failures are detected. 
 */
SSL_CTX* init_ssl(const server_config_t* config) {

    /* Setup the library */	
    SSL_library_init();
    SSL_load_error_strings();
    
    /* Create a context for receiving TLS connections. */
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    /* Use the referenced certificate file... */
    if (SSL_CTX_use_certificate_file(ctx, config->cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* ...and private key. */
    if (SSL_CTX_use_PrivateKey_file(ctx, config->key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}

/**
 * setup_tcp_socket takes the server configuration as an argument, and creates the TCP socket
 * used for accepting connections.  On errors, -1 is returned and an error printed to stderr.  
 * The caller is responsible for free-ing the socket returned. */

int setup_tcp_socket(const server_config_t* config) {
    /* Create a TCP/IPv4 socket. */	
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* Allow reuse of the local address.  (Useful for quickly restarting the server.) */
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "Failed to set socket options:%s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Bind to any local address, using the specified port. */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config->port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to bind to port %d. %s\n", config->port, strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Start listening for incoming connections for fileserver data. */
    if (listen(sock, 10) < 0) {
        fprintf(stderr, "Failed to listen on socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    return sock;
}


/* shutdown_server is a signal handler that halts the server */
void shutdown_server(int sig) {
    (void)sig; /* silence warnings about unused arguments. */

    /* Break the loop over the accept() system call. */
    keep_running = 0;

    /* Shutdown the listening socket.  This will cause accept() to return and accept no further connections. */
    if(listen_socket > 0) {
    	shutdown(listen_socket, SHUT_RDWR);
    }
}



/* TODO - probably in a separate password.c file. Here for testing/compiling */
int verify_password(const char* username, const char* password) {
    (void)username;
    (void)password;
    return 1;
}

/* main is the entrypoint and main thread of the server. */
int main(int argc, const char** argv) {
    /* Read the command line arguments. */	
    server_config_t* config = parse_args(argc, argv);
    if (!config) {
        return 1;
    }
    
    /* Setup the SSL library. */
    SSL_CTX* ssl_ctx = init_ssl(config);
    if (!ssl_ctx) {
        free(config);
        return 1;
    }
    
    /* Start a socket for listening for network connections. */
    listen_socket = setup_tcp_socket(config);
    if (listen_socket < 0) {
        SSL_CTX_free(ssl_ctx);
        free(config);
        return 1;
    }
    
    /* Register signal handlers for clean shutdowns. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shutdown_server;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    if (sigaction(SIGTERM, &sa, NULL) < 0 || sigaction(SIGINT, &sa, NULL) < 0) {
        fprintf(stderr, "Failed to setup signal handler\n");
        SSL_CTX_free(ssl_ctx);
        close(listen_socket);
        free(config);
        return 1;
    }
    
    printf("Server listening on port %d\n", config->port);

    /* Loop, listening for new connections and commands. */    
    while (keep_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_sock = accept(listen_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (keep_running) {
                fprintf(stderr, "Failed to accept connection\n");
            }
            continue;
        }

	/* Create a new context for the client. */	
        client_context_t* ctx = malloc(sizeof(client_context_t));
        if (!ctx) {
            close(client_sock);
            continue;
        }
        
        ctx->sock = client_sock;
        ctx->config = config;
        ctx->ssl_ctx = ssl_ctx;
        
	/* Create a detached pthread for handling the operation. */
        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        
        if (pthread_create(&thread, &attr, handle_client, ctx) != 0) {
            fprintf(stderr, "Failed to create thread\n");
            close(client_sock);
            free(ctx);
        }
        
        pthread_attr_destroy(&attr);
    }
    
    /* After receiving a signal to shut down, release resources, and exit, waiting on child threads to terminate. */
    SSL_CTX_free(ssl_ctx);
    close(listen_socket);
    free(config);
    
    pthread_exit(0);
    return 0;
}
