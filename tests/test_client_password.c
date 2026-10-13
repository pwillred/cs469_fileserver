/*
 * CS 469
 * Pseudo-terminal password tests. Child results never contain password bytes.
 */
#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE
#include "../client_password.h"
#include <openssl/crypto.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d\n",__LINE__); exit(1); } } while (0)

static void run_case(const char *input, size_t input_size, size_t capacity,
                     int expected, size_t expected_length, int interruption) {
    int master, slave;
    CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
    struct termios before, after;
    CHECK(tcgetattr(slave, &before) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        close(master);
        if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDERR_FILENO) < 0) _exit(2);
        close(slave);
        char buffer[CLIENT_PASSWORD_MAX + 2];
        memset(buffer, 'x', sizeof(buffer));
        int rc = client_read_password("Password: ", buffer, capacity);
        int good = rc == expected;
        if (rc == CLIENT_PASSWORD_OK) {
            good = good && strlen(buffer) == expected_length;
            for (size_t i = 0; i < expected_length; ++i) good = good && buffer[i] == 'q';
        } else {
            for (size_t i = 0; i < capacity; ++i) good = good && buffer[i] == 0;
        }
        OPENSSL_cleanse(buffer, sizeof(buffer));
        _exit(good ? 0 : 3);
    }
    char output[256] = {0};
    size_t used = 0;
    int sent = 0, done = 0, status = 0;
    for (int attempt = 0; attempt < 200; ++attempt) {
        fd_set ready;
        FD_ZERO(&ready); FD_SET(master, &ready);
        struct timeval timeout = {0, 50000};
        int rc = select(master + 1, &ready, NULL, NULL, &timeout);
        CHECK(rc >= 0 || errno == EINTR);
        if (rc > 0) {
            CHECK(used < sizeof(output) - 1);
            ssize_t n = read(master, output + used, sizeof(output) - used - 1);
            CHECK(n > 0);
            used += (size_t)n;
            output[used] = 0;
        }
        if (!sent && strstr(output, "Password: ") != NULL) {
            CHECK(tcgetattr(slave, &after) == 0 && !(after.c_lflag & ECHO));
            if (interruption != 0) {
                CHECK(kill(pid, interruption) == 0);
            } else {
                size_t offset = 0;
                while (offset < input_size) {
                    ssize_t n = write(master, input + offset, input_size - offset);
                    CHECK(n > 0);
                    offset += (size_t)n;
                }
            }
            sent = 1;
        }
        pid_t ended = waitpid(pid, &status, WNOHANG);
        CHECK(ended >= 0);
        if (ended == pid) { done = 1; break; }
    }
    if (!done) { kill(pid, SIGKILL); waitpid(pid, &status, 0); }
    CHECK(done && sent && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* No input character occurs in the fixed prompt; even one echoed q fails. */
    CHECK(strchr(output, 'q') == NULL);
    CHECK(tcgetattr(slave, &after) == 0);
    CHECK(before.c_iflag == after.c_iflag && before.c_oflag == after.c_oflag &&
          before.c_cflag == after.c_cflag && before.c_lflag == after.c_lflag);
    CHECK(memcmp(before.c_cc, after.c_cc, sizeof(before.c_cc)) == 0);
    CHECK(cfgetispeed(&before) == cfgetispeed(&after) && cfgetospeed(&before) == cfgetospeed(&after));
    CHECK(close(master) == 0 && close(slave) == 0);
}

int main(void) {
    run_case("qqqq\n", 5, 4097, CLIENT_PASSWORD_OK, 4, 0);
    run_case("\n", 1, 4097, CLIENT_PASSWORD_EMPTY, 0, 0);
    run_case("qq\004", 3, 4097, CLIENT_PASSWORD_INPUT_ERROR, 0, 0);
    run_case("qq\0q\n", 5, 4097, CLIENT_PASSWORD_INPUT_ERROR, 0, 0);
    run_case("qqqq\n", 5, 4, CLIENT_PASSWORD_TOO_LONG, 0, 0);
    run_case("qqq\n", 4, 4, CLIENT_PASSWORD_OK, 3, 0);
    char maximum[4099];
    memset(maximum, 'q', sizeof(maximum));
    maximum[4096] = '\n';
    run_case(maximum, 4097, 4097, CLIENT_PASSWORD_OK, 4096, 0);
    maximum[4096] = 'q'; maximum[4097] = '\n';
    run_case(maximum, 4098, 4098, CLIENT_PASSWORD_TOO_LONG, 0, 0);
    int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    for (size_t i = 0; i < sizeof(signals)/sizeof(signals[0]); ++i) {
        run_case(NULL, 0, 4097, CLIENT_PASSWORD_INTERRUPTED, 0, signals[i]);
    }
    char buffer[8];
    memset(buffer, 'x', sizeof(buffer));
    CHECK(client_read_password(NULL, buffer, sizeof(buffer)) == CLIENT_PASSWORD_INVALID_ARGUMENT);
    for (size_t i = 0; i < sizeof(buffer); ++i) CHECK(buffer[i] == 0);
    CHECK(client_read_password("Password: ", NULL, 8) == CLIENT_PASSWORD_INVALID_ARGUMENT);
    CHECK(client_read_password("Password: ", buffer, 1) == CLIENT_PASSWORD_INVALID_ARGUMENT);
    int saved = dup(STDIN_FILENO), nonterminal = open("/dev/null", O_RDONLY);
    CHECK(saved >= 0 && nonterminal >= 0 && dup2(nonterminal, STDIN_FILENO) >= 0);
    memset(buffer, 'x', sizeof(buffer));
    CHECK(client_read_password("Password: ", buffer, sizeof(buffer)) == CLIENT_PASSWORD_NOT_TERMINAL);
    for (size_t i = 0; i < sizeof(buffer); ++i) CHECK(buffer[i] == 0);
    CHECK(dup2(saved, STDIN_FILENO) >= 0);
    CHECK(close(saved) == 0 && close(nonterminal) == 0);
    OPENSSL_cleanse(maximum, sizeof(maximum));
    puts("PASS: 12 terminal cases plus argument/nonterminal checks; echo, cleanup and restoration verified");
    return 0;
}
