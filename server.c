/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * server.c provides the main function and handler threads for the server side of the fileserver.
 */

#include "protocol.h"
#include "server.h"
#include "server_replication.h"
#include "password_db.h"
#include "password.h"
#include <limits.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h>

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

/* Global config struct - we only need one, and having it be free()d is challenging - what if worker threads outlast main? */
static server_config_t config;

static int positive_number(const char *text, int maximum) {
    if (!text || !*text) return 0;
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return 0;
    errno = 0;
    char *end;
    long value = strtol(text, &end, 10);
    return errno || *end || value < 1 || value > maximum ? 0 : (int)value;
}

server_config_t* parse_args(int argc, const char** argv) {
    config.timeout_sec = DEFAULT_TIMEOUT;
    config.role = ROLE_PRIMARY;
    config.replication_port = DEFAULT_REPLICATION_PORT;
    config.coordinator_name = "primary.localhost";
    config.peer_cert_path = NULL;
   
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            config.port = positive_number(argv[++i], 65535);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config.cert_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            config.key_path = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            config.data_dir = argv[++i];
        } else if (strcmp(argv[i], "--auth-db") == 0 && i + 1 < argc) {
            config.auth_db_path = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            config.timeout_sec = positive_number(argv[++i], INT_MAX / 1000);
        } else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            const char* role_arg = argv[++i];
            if (strcmp(role_arg, "primary") == 0) {
                config.role = ROLE_PRIMARY;
            } else if (strcmp(role_arg, "replica") == 0) {
                config.role = ROLE_REPLICA;
            } else {
                fprintf(stderr, "Unknown role: %s\n", role_arg);
                return NULL;
            }
        } else if (strcmp(argv[i], "--replication-port") == 0 && i + 1 < argc) {
            config.replication_port = positive_number(argv[++i], 65535);
        } else if (strcmp(argv[i], "--coordinator-name") == 0 && i + 1 < argc) {
            config.coordinator_name = argv[++i];
        } else if (strcmp(argv[i], "--peer-cert") == 0 && i + 1 < argc) {
            config.peer_cert_path = argv[++i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return NULL;
        }
    }
    
    if (config.port < 1 || config.port > 65535 || !config.cert_path || !config.key_path || !config.data_dir ||
        !config.auth_db_path || !*config.auth_db_path || config.timeout_sec < 1 || config.timeout_sec > INT_MAX / 1000) {
        fprintf(stderr, "Usage: %s -p port -c cert -k key -d data_dir --auth-db PATH [--timeout seconds] [--role {primary,replica}] [--replication-port port] [--coordinator-name name] [--peer-cert PATH]\n", argv[0]);
        return NULL;
    }
    
    if (config.role == ROLE_REPLICA && !config.peer_cert_path) {
        fprintf(stderr, "Replica mode requires --peer-cert to verify primary's client certificate\n");
        return NULL;
    }
    
    return &config;
}

SSL_CTX* init_ssl(const server_config_t* config) {
    SSL_library_init();
    SSL_load_error_strings();
    
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    if (SSL_CTX_use_certificate_file(ctx, config->cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, config->key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}

int setup_tcp_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "Failed to set socket options:%s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to bind to port %d. %s\n", port, strerror(errno));
        close(sock);
        return -1;
    }
    
    if (listen(sock, 10) < 0) {
        fprintf(stderr, "Failed to listen on socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    return sock;
}

static volatile sig_atomic_t keep_running = 1;
static volatile int listen_socket = -1;
static volatile int replication_socket = -1;

void shutdown_server(int sig) {
    (void)sig;
    keep_running = 0;
}

int main(int argc, const char** argv) {
    server_config_t* config = parse_args(argc, argv);
    if (!config) {
        return 1;
    }
    
    password_db_t *auth_db = NULL;
    int db_result = password_db_open_existing(config->auth_db_path, &auth_db);
    if (db_result == PASSWORD_DB_OK) db_result = password_db_check_schema(auth_db);
    password_db_close(auth_db);
    if (db_result != PASSWORD_DB_OK) {
        fprintf(stderr, "Authentication DB preflight failed; provision an existing valid users DB via admin\n");
        free(config);
        return 1;
    }
    
    struct sigaction pipe_action;
    memset(&pipe_action, 0, sizeof(pipe_action));
    pipe_action.sa_handler = SIG_IGN;
    sigemptyset(&pipe_action.sa_mask);
    if (sigaction(SIGPIPE, &pipe_action, NULL) < 0) { free(config); return 1; }

    SSL_CTX* ssl_ctx = init_ssl(config);
    if (!ssl_ctx) {
        free(config);
        return 1;
    }
    
    SSL_CTX* replication_ssl_ctx = NULL;
    
    if (config->role == ROLE_REPLICA) {
        replication_ssl_ctx = init_replication_ssl(config);
        if (!replication_ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
            free(config);
            return 1;
        }
        
        replication_socket = setup_tcp_socket(config->replication_port);
        if (replication_socket < 0) {
            SSL_CTX_free(ssl_ctx);
            SSL_CTX_free(replication_ssl_ctx);
            free(config);
            return 1;
        }
        
        int flags = fcntl(replication_socket, F_GETFL);
        if (flags < 0 || fcntl(replication_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
            SSL_CTX_free(ssl_ctx); SSL_CTX_free(replication_ssl_ctx);
            close(listen_socket); close(replication_socket); free(config); return 1;
        }
    }
    
    listen_socket = setup_tcp_socket(config->port);
    if (listen_socket < 0) {
        SSL_CTX_free(ssl_ctx);
        SSL_CTX_free(replication_ssl_ctx);
        free(config);
        return 1;
    }
    
    int flags = fcntl(listen_socket, F_GETFL);
    if (flags < 0 || fcntl(listen_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        SSL_CTX_free(ssl_ctx); SSL_CTX_free(replication_ssl_ctx); close(listen_socket); close(replication_socket); free(config); return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shutdown_server;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    if (sigaction(SIGTERM, &sa, NULL) < 0 || sigaction(SIGINT, &sa, NULL) < 0) {
        fprintf(stderr, "Failed to setup signal handler\n");
        SSL_CTX_free(ssl_ctx);
        SSL_CTX_free(replication_ssl_ctx);
        close(listen_socket);
        close(replication_socket);
        free(config);
        return 1;
    }
    
    if (config->role == ROLE_REPLICA) {
        printf("Server listening on port %d (client) and %d (replication)\n", config->port, config->replication_port);
    } else {
        printf("Server listening on port %d\n", config->port);
    }
    fflush(stdout);
   
    while (keep_running) {
        struct pollfd listeners[2] = {{listen_socket, POLLIN, 0}, {replication_socket, POLLIN, 0}};
        int ready = poll(listeners, 2, 500);
        if (!keep_running) break;
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || listeners[0].revents & (POLLERR | POLLHUP | POLLNVAL) || listeners[1].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (ready == 0) continue;
            
        for (int i = 0; i < 2; i++) {
            if (listeners[i].revents & POLLIN) {
                int sock = (i == 0) ? listen_socket : replication_socket;
                int client_sock = accept(sock, NULL, NULL);
                if (client_sock < 0) {
                    if (keep_running) fprintf(stderr, "Failed to accept connection\n");
                    continue;
                }
                  
                int client_flags = fcntl(client_sock, F_GETFL);
                if (client_flags < 0 || fcntl(client_sock, F_SETFL, client_flags & ~O_NONBLOCK) < 0) {
                    close(client_sock); continue;
                }
                    
                client_context_t* ctx = calloc(1, sizeof(client_context_t));
                if (!ctx) {
                     close(client_sock);
                     break;
                }
                      
                ctx->sock = client_sock;
                ctx->config = config;

		if (i == 0) {
			if (SSL_CTX_up_ref(ssl_ctx) != 1) {
				close(client_sock);
				free(ctx);
				continue;
			}
			ctx->ssl_ctx = ssl_ctx;
		} else {
			if (SSL_CTX_up_ref(replication_ssl_ctx) != 1) {
				close(client_sock);
				free(ctx);
				continue;
			}
			ctx->ssl_ctx = replication_ssl_ctx;
		}
                        
                pthread_t thread;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                       
	        if (i == 0) {
		    if (pthread_create(&thread, &attr, handle_client, ctx) != 0) {
                        fprintf(stderr, "Failed to create thread\n");
		    }
		} else {
		    if (pthread_create(&thread, &attr, replication_handler, ctx) != 0) {
		        fprintf(stderr, "Failed to create thread\n");
		    }
		}
                        
                pthread_attr_destroy(&attr);
            }
        }
    }
    
    SSL_CTX_free(ssl_ctx);

    if (config->role == ROLE_REPLICA) {
        SSL_CTX_free(replication_ssl_ctx);
    	close(replication_socket);
    }

    close(listen_socket);
    
    pthread_exit(0);
    return 0;
}
