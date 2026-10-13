#define _DARWIN_C_SOURCE
#include "../server_read_ops.h"
#include "../server_protocol_io.h"
#include "../password_db.h"
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "fixture failure line %d\n", __LINE__); exit(1); } } while (0)
struct worker { int fd; SSL_CTX *tls; server_read_context_t context; };
static void *serve(void *arg) {
    struct worker *w = arg;
    struct timeval timeout = {3, 0};
    setsockopt(w->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(w->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    SSL *ssl = SSL_new(w->tls); CHECK(ssl && SSL_set_fd(ssl, w->fd) == 1);
    if (SSL_accept(ssl) == 1) {
        server_protocol_io_t state; server_read_io_t io;
        CHECK(server_protocol_io_init(&state, ssl, 3000, &io) == 0);
        char verb[8]; server_read_result_t result = {ERR_INTERNAL, 0};
        if (io.read_exact(io.state, verb, 4) == 0) {
            if (!memcmp(verb, "LIST", 4)) result = server_handle_list(&io, &w->context);
            else if (!memcmp(verb, "DOWN", 4) && io.read_exact(io.state, verb + 4, 4) == 0 &&
                     !memcmp(verb, "DOWNLOAD", 8)) result = server_handle_download(&io, &w->context);
        }
        if (!result.complete) { io.abort(io.state); fprintf(stderr, "read fixture: incomplete response\n"); }
        else (void)SSL_shutdown(ssl);
    }
    SSL_free(ssl); close(w->fd); free(w); return NULL;
}
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--init")) {
        password_db_t *db = NULL; CHECK(password_db_open(argv[2], &db) == 0);
        CHECK(password_db_init_schema(db) == 0);
        CHECK(password_db_add_user(db, "alice", "secret") == 0);
        CHECK(password_db_add_user(db, "bob", "secret") == 0);
        char user[65], password[65]; memset(user, 'u', 64); user[64] = 0;
        memset(password, 'p', 64); password[64] = 0;
        CHECK(password_db_add_user(db, user, password) == 0);
        password_db_close(db); return 0;
    }
    CHECK(argc == 5);
    /* Fixture-only handshake/shutdown signal policy; adapter independently guards
     * its calls. Production startup policy is deliberately not changed. */
    signal(SIGPIPE, SIG_IGN);
    SSL_CTX *tls = SSL_CTX_new(TLS_server_method()); CHECK(tls);
    CHECK(SSL_CTX_set_min_proto_version(tls, TLS1_2_VERSION) == 1);
    CHECK(SSL_CTX_use_certificate_chain_file(tls, argv[1]) == 1);
    CHECK(SSL_CTX_use_PrivateKey_file(tls, argv[2], SSL_FILETYPE_PEM) == 1);
    int listener = socket(AF_INET, SOCK_STREAM, 0); CHECK(listener >= 0);
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 && listen(listener, 32) == 0);
    socklen_t length = sizeof(address); CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0);
    printf("%u\n", ntohs(address.sin_port)); fflush(stdout);
    pthread_t threads[512]; size_t count = 0;
    for (;;) {
        struct pollfd descriptors[2] = {{listener, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};
        CHECK(poll(descriptors, 2, 15000) > 0);
        if (descriptors[1].revents) break;
        if (descriptors[0].revents & POLLIN) {
            CHECK(count < sizeof(threads)/sizeof(threads[0]));
            struct worker *w = malloc(sizeof(*w)); CHECK(w);
            *w = (struct worker){accept(listener, NULL, NULL), tls, {argv[3], argv[4]}};
            CHECK(w->fd >= 0 && pthread_create(&threads[count++], NULL, serve, w) == 0);
        }
    }
    close(listener);
    for (size_t i = 0; i < count; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    SSL_CTX_free(tls); return 0;
}
