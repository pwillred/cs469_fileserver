/* Command runner for the TLS integration harness. Verifies full password erasure
 * on every tested path. Only this test build substitutes local file I/O faults. */
#define _POSIX_C_SOURCE 200809L
#include "../client_commands.h"
#include "../client_password.h"
#include "client_io_faults.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
ssize_t client_test_read(int fd, void *buffer, size_t size) {
    if (getenv("CS469_TEST_READ_FAIL")) { errno = EIO; return -1; }
    /* Also force legitimate short local reads for every successful upload. */
    return read(fd, buffer, size > 1009 ? 1009 : size);
}
ssize_t client_test_write(int fd, const void *buffer, size_t size) {
    if (getenv("CS469_TEST_WRITE_FAIL")) { errno = ENOSPC; return -1; }
    return write(fd, buffer, size > 509 ? 509 : size);
}
int main(int argc, char **argv) {
    (void)signal(SIGPIPE, SIG_IGN);
    client_options_t options;
    const char *error = NULL;
    if (client_parse_options(argc, argv, &options, &error) != CLIENT_PARSE_OK ||
        client_config_load(options.config_path, &options.deployment, &error) != CLIENT_PARSE_OK) return 90;
    char password[CLIENT_PASSWORD_MAX + 1];
    memset(password, 0x7f, sizeof(password));
    size_t length = getenv("CS469_TEST_LONG_PASSWORD") ? 65 : 8;
    memset(password, 'q', length); password[length] = 0;
    client_command_result_t result = client_execute(&options, password, sizeof(password), stdout);
    for (size_t i = 0; i < sizeof(password); ++i) if (password[i] != 0) return 91;
    fprintf(stderr, "CLEANSED kind=%d transport=%d status=%d\n%s\n", result.kind, result.transport, result.status, result.message);
    return result.kind == CLIENT_RESULT_OK ? 0 : 1;
}
