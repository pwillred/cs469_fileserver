/*
 * CS 469
 * Loopback TLS fixtures: ephemeral keys/certificates, no external server.
 */
#define _POSIX_C_SOURCE 200809L
#include "../client_transport.h"
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); goto cleanup; } } while (0)
#define PAYLOAD_SIZE (256 * 1024)
enum { DATA, CLEAN_EOF, ABRUPT, HANDSHAKE_STALL, READ_STALL, REJECT, PLAIN, HANDSHAKE_LOSS };

static EVP_PKEY *new_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    if (ctx == NULL) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) { EVP_PKEY_free(key); key = NULL; }
    EVP_PKEY_CTX_free(ctx);
    return key;
}
static int extension(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ext == NULL) return 0;
    int ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return ok;
}
static X509 *certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key,
                         const char *name, const char *san, long serial) {
    X509 *cert = X509_new();
    if (cert == NULL) return NULL;
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!X509_set_version(cert, 2) || !ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) ||
        X509_gmtime_adj(X509_getm_notBefore(cert), -60) == NULL ||
        X509_gmtime_adj(X509_getm_notAfter(cert), 3600) == NULL ||
        !X509_set_pubkey(cert, key) ||
        !X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)name, -1, -1, 0) ||
        !X509_set_issuer_name(cert, issuer ? X509_get_subject_name(issuer) : subject) ||
        !extension(cert, issuer ? issuer : cert, NID_basic_constraints, issuer ? "critical,CA:FALSE" : "critical,CA:TRUE") ||
        !extension(cert, issuer ? issuer : cert, NID_key_usage, issuer ? "critical,digitalSignature,keyEncipherment" : "critical,keyCertSign,cRLSign")) goto fail;
    if (issuer && (!extension(cert, issuer, NID_ext_key_usage, "serverAuth") ||
                   !extension(cert, issuer, NID_subject_alt_name, san))) goto fail;
    if (!X509_sign(cert, issuer_key ? issuer_key : key, EVP_sha256())) goto fail;
    return cert;
fail:
    X509_free(cert);
    return NULL;
}
static int save_ca(char *path, X509 *cert) {
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    FILE *file = fdopen(fd, "w");
    if (file == NULL) { close(fd); return 0; }
    int ok = PEM_write_X509(file, cert);
    return fclose(file) == 0 && ok == 1;
}
static int listen_local(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) goto fail;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, 8) < 0) goto fail;
    socklen_t n = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &n) < 0) goto fail;
    *port = ntohs(addr.sin_port);
    return fd;
fail:
    close(fd); return -1;
}
static void pause_ms(long ms) {
    struct timespec delay = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
}
static int serve_one(int listener, SSL_CTX *ctx, int mode, int expect_sni) {
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) return 0;
    struct timeval timeout = {3, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) { close(fd); return 0; }
    if (mode == HANDSHAKE_STALL) { pause_ms(300); close(fd); return 1; }
    if (mode == HANDSHAKE_LOSS) { close(fd); return 1; }
    if (mode == PLAIN) { int ok = write(fd, "not TLS\n", 8) == 8; close(fd); return ok; }
    SSL *ssl = SSL_new(ctx);
    int ok = 0;
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1) goto done;
    int accepted = SSL_accept(ssl);
    if (mode == REJECT) { ok = accepted <= 0; goto done; }
    if (accepted != 1) goto done;
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (expect_sni ? (sni == NULL || strcmp(sni, "localhost") != 0) : sni != NULL) goto done;
    if (mode == ABRUPT) { ok = 1; goto done; }
    if (mode == READ_STALL) { pause_ms(300); ok = 1; goto done; }
    if (mode == CLEAN_EOF) { ok = SSL_shutdown(ssl) >= 0; goto done; }
    /* One record split across two client reads; withhold further network data
     * until client consumes its buffered suffix and sends an acknowledgement.
     */
    if (SSL_write(ssl, "abcde", 5) != 5) goto done;
    char byte;
    if (SSL_read(ssl, &byte, 1) != 1 || byte != 'A') goto done;
    if (SSL_write(ssl, "xy", 2) != 2) goto done;
    pause_ms(20);
    if (SSL_write(ssl, "z", 1) != 1) goto done;
    size_t total = 0;
    char buffer[1009];
    while (total < PAYLOAD_SIZE) {
        size_t want = PAYLOAD_SIZE - total < sizeof(buffer) ? PAYLOAD_SIZE - total : sizeof(buffer);
        int n = SSL_read(ssl, buffer, (int)want);
        if (n <= 0) goto done;
        for (int i = 0; i < n; ++i) if (buffer[i] != 'Q') goto done;
        total += (size_t)n;
    }
    ok = SSL_write(ssl, "Z", 1) == 1;
    if (ok) (void)SSL_shutdown(ssl);
done:
    SSL_free(ssl);
    close(fd);
    return ok;
}
static pid_t spawn_server(uint16_t *port, EVP_PKEY *key, X509 *cert,
                          int mode, int connections, int expect_sni) {
    int listener = listen_local(port);
    if (listener < 0) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        alarm(15);
        (void)signal(SIGPIPE, SIG_IGN); /* Fixture only, never production client. */
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        int ok = ctx != NULL && SSL_CTX_use_certificate(ctx, cert) == 1 && SSL_CTX_use_PrivateKey(ctx, key) == 1;
        for (int i = 0; ok && i < connections; ++i) ok = serve_one(listener, ctx, mode, expect_sni);
        SSL_CTX_free(ctx);
        close(listener);
        _exit(ok ? 0 : 2);
    }
    close(listener);
    return pid;
}
static int reap(pid_t *pid) {
    int status;
    pid_t rc;
    do { rc = waitpid(*pid, &status, 0); } while (rc < 0 && errno == EINTR);
    *pid = -1;
    return rc > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int descriptor_count(void) {
    int count = 0;
    for (int i = 0; i < 1024; ++i) if (fcntl(i, F_GETFD) >= 0) ++count;
    return count;
}

int main(void) {
    int result = EXIT_FAILURE;
    EVP_PKEY *key = NULL, *other_key = NULL;
    X509 *ca = NULL, *other_ca = NULL, *leaf = NULL, *wrong = NULL;
    char ca_path[] = "/tmp/cs469-ca-XXXXXX", other_path[] = "/tmp/cs469-other-ca-XXXXXX";
    client_connection_t *c = NULL;
    pid_t child = -1;
    char *payload = NULL;
    client_endpoint_t endpoint = {"127.0.0.1", 1};
    CHECK(client_connection_open(NULL, "ca", &c) == CLIENT_TRANSPORT_INVALID_ARGUMENT && c == NULL);
    CHECK(client_connection_open(&endpoint, NULL, &c) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    CHECK(client_connection_open(&endpoint, "", &c) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    CHECK(client_connection_open(&endpoint, "ca", NULL) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    CHECK(client_connection_open_timeout(&endpoint, "ca", 0, &c) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    endpoint.port = 0;
    CHECK(client_connection_open(&endpoint, "ca", &c) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    endpoint.port = 1;
    memset(endpoint.host, 'x', sizeof(endpoint.host));
    CHECK(client_connection_open(&endpoint, "ca", &c) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    strcpy(endpoint.host, "127.0.0.1");
    CHECK(client_connection_read_exact(NULL, NULL, 0) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    CHECK(client_connection_write_all(NULL, NULL, 0) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
    client_connection_close(NULL);
    puts("PASS: invalid arguments and NULL cleanup");
    key = new_key(); other_key = new_key();
    CHECK(key != NULL && other_key != NULL);
    ca = certificate(key, NULL, NULL, "Temporary test CA", NULL, 1);
    other_ca = certificate(other_key, NULL, NULL, "Other test CA", NULL, 2);
    CHECK(ca != NULL && other_ca != NULL);
    leaf = certificate(key, ca, key, "localhost", "DNS:localhost,IP:127.0.0.1,IP:::1", 3);
    wrong = certificate(key, ca, key, "other.example", "DNS:other.example,IP:127.0.0.2", 4);
    CHECK(leaf != NULL && wrong != NULL && save_ca(ca_path, ca) && save_ca(other_path, other_ca));
    /* macOS lazily retains resolver infrastructure descriptors. Initialize
     * numeric and hostname resolution independently of the transport first. */
    struct addrinfo hints = {0}, *resolved = NULL;
    hints.ai_socktype = SOCK_STREAM;
    const char *hosts[] = {"256.256.256.256", "localhost", "127.0.0.1"};
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        if (getaddrinfo(hosts[i], "1", &hints, &resolved) == 0) freeaddrinfo(resolved);
    }
    int baseline = descriptor_count();
    CHECK(client_connection_open(&endpoint, "/nonexistent/cs469-ca", &c) == CLIENT_TRANSPORT_TLS_CA_ERROR && c == NULL);
    /* Invalid numeric host exercises getaddrinfo failure. */
    strcpy(endpoint.host, "256.256.256.256");
    CHECK(client_connection_open(&endpoint, ca_path, &c) == CLIENT_TRANSPORT_RESOLVE_ERROR && c == NULL);
    strcpy(endpoint.host, "127.0.0.1");
    int reserved = listen_local(&endpoint.port);
    CHECK(reserved >= 0);
    CHECK(close(reserved) == 0);
    CHECK(client_connection_open(&endpoint, ca_path, &c) == CLIENT_TRANSPORT_CONNECT_ERROR && c == NULL);
    puts("PASS: CA configuration, resolver and refused connection classification");
    CHECK(descriptor_count() == baseline);

    payload = malloc(PAYLOAD_SIZE);
    CHECK(payload != NULL);
    memset(payload, 'Q', PAYLOAD_SIZE);
    for (int dns = 0; dns < 2; ++dns) {
        strcpy(endpoint.host, dns ? "localhost" : "127.0.0.1");
        child = spawn_server(&endpoint.port, key, leaf, DATA, 3, dns);
        CHECK(child > 0);
        for (int i = 0; i < 3; ++i) {
            CHECK(client_connection_open(&endpoint, ca_path, &c) == CLIENT_TRANSPORT_OK && c != NULL);
            CHECK(client_connection_read_exact(c, NULL, 0) == CLIENT_TRANSPORT_OK);
            CHECK(client_connection_write_all(c, NULL, 0) == CLIENT_TRANSPORT_OK);
            CHECK(client_connection_read_exact(c, NULL, 1) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
            CHECK(client_connection_write_all(c, NULL, 1) == CLIENT_TRANSPORT_INVALID_ARGUMENT);
            char data[5];
            CHECK(client_connection_read_exact(c, data, 2) == CLIENT_TRANSPORT_OK && memcmp(data, "ab", 2) == 0);
            CHECK(client_connection_read_exact(c, data, 3) == CLIENT_TRANSPORT_OK && memcmp(data, "cde", 3) == 0);
            CHECK(client_connection_write_all(c, "A", 1) == CLIENT_TRANSPORT_OK);
            CHECK(client_connection_read_exact(c, data, 3) == CLIENT_TRANSPORT_OK && memcmp(data, "xyz", 3) == 0);
            CHECK(client_connection_write_all(c, payload, PAYLOAD_SIZE) == CLIENT_TRANSPORT_OK);
            CHECK(client_connection_read_exact(c, data, 1) == CLIENT_TRANSPORT_OK && data[0] == 'Z');
            CHECK(client_connection_read_exact(c, data, 1) == CLIENT_TRANSPORT_EOF);
            client_connection_close(c); c = NULL;
        }
        CHECK(reap(&child));
    }
    puts("PASS: repeated verified DNS/IP connections, SNI, coalesced/fragmented reads, large writes and clean EOF");
    CHECK(descriptor_count() == baseline);
    for (int i = 0; i < 3; ++i) {
        strcpy(endpoint.host, i == 1 ? "localhost" : "127.0.0.1");
        child = spawn_server(&endpoint.port, key, i == 0 ? leaf : wrong, REJECT, 1, i == 1);
        CHECK(child > 0);
        CHECK(client_connection_open(&endpoint, i == 0 ? other_path : ca_path, &c) == CLIENT_TRANSPORT_TLS_VERIFY_ERROR && c == NULL);
        CHECK(reap(&child));
    }
    puts("PASS: untrusted certificate, DNS mismatch and IP mismatch fail closed");
    strcpy(endpoint.host, "127.0.0.1");
    int modes[] = {ABRUPT, HANDSHAKE_STALL, READ_STALL, PLAIN, HANDSHAKE_LOSS, CLEAN_EOF};
    for (size_t i = 0; i < sizeof(modes)/sizeof(modes[0]); ++i) {
        child = spawn_server(&endpoint.port, key, leaf, modes[i], 1, 0);
        CHECK(child > 0);
        int rc = client_connection_open_timeout(&endpoint, ca_path, 100, &c);
        if (modes[i] == HANDSHAKE_STALL) CHECK(rc == CLIENT_TRANSPORT_TIMEOUT && c == NULL);
        else if (modes[i] == PLAIN) CHECK(rc == CLIENT_TRANSPORT_TLS_HANDSHAKE_ERROR && c == NULL);
        else if (modes[i] == HANDSHAKE_LOSS) CHECK(rc == CLIENT_TRANSPORT_IO_ERROR && c == NULL);
        else {
            CHECK(rc == CLIENT_TRANSPORT_OK);
            char data;
            rc = client_connection_read_exact(c, &data, 1);
            CHECK(rc == (modes[i] == READ_STALL ? CLIENT_TRANSPORT_TIMEOUT :
                         modes[i] == CLEAN_EOF ? CLIENT_TRANSPORT_EOF : CLIENT_TRANSPORT_IO_ERROR));
            client_connection_close(c); c = NULL;
        }
        CHECK(reap(&child));
    }
    CHECK(descriptor_count() == baseline);
    puts("PASS: handshake/read deadlines, plaintext rejection, abrupt loss, sequential failures and descriptor accounting");
    result = EXIT_SUCCESS;
cleanup:
    client_connection_close(c);
    if (child > 0) { kill(child, SIGKILL); (void)reap(&child); }
    free(payload);
    X509_free(wrong); X509_free(leaf); X509_free(other_ca); X509_free(ca);
    EVP_PKEY_free(other_key); EVP_PKEY_free(key);
    if (access(ca_path, F_OK) == 0 && unlink(ca_path) != 0) result = EXIT_FAILURE;
    if (access(other_path, F_OK) == 0 && unlink(other_path) != 0) result = EXIT_FAILURE;
    if (result == EXIT_SUCCESS) puts("All transport tests passed; temporary certificates removed.");
    return result;
}
