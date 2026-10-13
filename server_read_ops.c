#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "server_read_ops.h"
#include "server_auth.h"
#include <openssl/crypto.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static server_read_result_t failed(const server_read_io_t *io) {
    if (io && io->abort) io->abort(io->state);
    return (server_read_result_t){ERR_INTERNAL, 0};
}
static int status_byte(const server_read_io_t *io, error_code_t status) {
    uint8_t byte;
    switch (status) {
        case ERR_OK: byte = 0; break;
        case ERR_AUTH_FAILED: byte = 1; break;
        case ERR_NOT_FOUND: byte = 2; break;
        case ERR_EXISTS: byte = 3; break;
        case ERR_BAD_REQUEST: byte = 4; break;
        case ERR_TOO_LARGE: byte = 5; break;
        case ERR_REPLICATION_FAILED: byte = 6; break;
        default: byte = 7; break;
    }
    return io->write_all(io->state, &byte, 1);
}
static server_read_result_t error_response(const server_read_io_t *io, error_code_t status) {
    if (status_byte(io, status) != 0) return failed(io);
    return (server_read_result_t){status, 1};
}
static int number(const server_read_io_t *io, uint32_t n) {
    uint8_t b[4] = {(uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n};
    return io->write_all(io->state, b, sizeof(b));
}
static size_t field(const server_read_io_t *io, char *out, size_t capacity) {
    for (size_t i = 0; i < capacity; ++i) {
        if (io->read_exact(io->state, out + i, 1) != 0) return 0;
        if (out[i] == 0) return i + 1;
    }
    return 0;
}
static int valid_name(const char *name) {
    size_t n = strnlen(name, MAX_FILENAME_LEN + 1);
    if (!n || n > MAX_FILENAME_LEN || !strcmp(name, ".") || !strcmp(name, "..")) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (c < 32 || c > 126 || c == '/' || c == '\\') return 0;
    }
    return 1;
}
static int internal_name(const char *name) { return strncmp(name, ".temp_", 6) == 0; }
static error_code_t credentials(const server_read_io_t *io, const server_read_context_t *ctx,
                                 char user[65], char *name) {
    char password[65] = {0};
    error_code_t status = ERR_BAD_REQUEST;
    size_t u = field(io, user, 65), p = 0;
    if (u) p = field(io, password, sizeof(password));
    if (!u || !p || (name && !field(io, name, MAX_FILENAME_LEN + 1))) goto done;
    status = server_auth_to_error(server_auth_verify(ctx->auth_db_path, user, u, password, p));
    if (status == ERR_OK && name && !valid_name(name)) status = ERR_BAD_REQUEST;
done:
    OPENSSL_cleanse(password, sizeof(password));
    return status;
}
/* Open the root once, then resolve only validated single-component names. Root
 * ancestors are trusted configuration. Never follow a user directory symlink. */
static error_code_t user_directory(const server_read_context_t *ctx, const char *user, int *out) {
    int root = open(ctx->data_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return ERR_INTERNAL;
    *out = openat(root, user, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved = errno;
    close(root);
    if (*out >= 0) return ERR_OK;
    return saved == ENOENT ? ERR_NOT_FOUND : ERR_INTERNAL;
}
static int compare_names(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}
static int usable(const server_read_io_t *io, const server_read_context_t *ctx) {
    return io && io->read_exact && io->write_all && io->abort && ctx && ctx->data_dir && *ctx->data_dir;
}
server_read_result_t server_handle_list(const server_read_io_t *io, const server_read_context_t *ctx) {
    if (!usable(io, ctx)) return failed(io);
    char user[65];
    error_code_t status = credentials(io, ctx, user, NULL);
    if (status != ERR_OK) return error_response(io, status);
    int fd = -1;
    status = user_directory(ctx, user, &fd);
    if (status != ERR_OK && status != ERR_NOT_FOUND) return error_response(io, status);
    char **names = NULL;
    size_t count = 0;
    DIR *dir = NULL;
    if (fd >= 0) {
        dir = fdopendir(fd);
        if (!dir) { close(fd); return error_response(io, ERR_INTERNAL); }
        names = calloc(SERVER_READ_LIST_MAX, sizeof(*names));
        if (!names) { closedir(dir); return error_response(io, ERR_INTERNAL); }
        for (;;) {
            errno = 0;
            struct dirent *entry = readdir(dir);
            if (!entry) { if (errno) status = ERR_INTERNAL; break; }
            if (!valid_name(entry->d_name) || internal_name(entry->d_name)) continue;
            struct stat st;
            if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno == ENOENT) continue; /* concurrent committed delete */
                status = ERR_INTERNAL; break;
            }
            if (!S_ISREG(st.st_mode)) continue;
            if (count == SERVER_READ_LIST_MAX) { status = ERR_INTERNAL; break; }
            names[count] = strdup(entry->d_name);
            if (!names[count]) { status = ERR_INTERNAL; break; }
            ++count;
        }
        if (closedir(dir) < 0) status = ERR_INTERNAL;
    } else status = ERR_OK; /* authenticated user with no directory */
    server_read_result_t result;
    if (status != ERR_OK) result = error_response(io, status);
    else {
        if (count > 1) qsort(names, count, sizeof(*names), compare_names);
        int bad = status_byte(io, ERR_OK) != 0;
        if (!bad) bad = number(io, (uint32_t)count) != 0;
        for (size_t i = 0; !bad && i < count; ++i)
            bad = io->write_all(io->state, names[i], strlen(names[i]) + 1) != 0;
        result = bad ? failed(io) : (server_read_result_t){ERR_OK, 1};
    }
    for (size_t i = 0; i < count; ++i) free(names[i]);
    free(names);
    return result;
}
server_read_result_t server_handle_download(const server_read_io_t *io, const server_read_context_t *ctx) {
    if (!usable(io, ctx)) return failed(io);
    char user[65], name[MAX_FILENAME_LEN + 1];
    error_code_t status = credentials(io, ctx, user, name);
    if (status != ERR_OK) return error_response(io, status);
    if (internal_name(name)) return error_response(io, ERR_NOT_FOUND);
    int dir = -1;
    status = user_directory(ctx, user, &dir);
    if (status != ERR_OK) return error_response(io, status);
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int saved = errno;
    close(dir);
    if (fd < 0) return error_response(io, saved == ENOENT || saved == ELOOP ? ERR_NOT_FOUND : ERR_INTERNAL);
    struct stat st;
    if (fstat(fd, &st) < 0) status = ERR_INTERNAL;
    else if (!S_ISREG(st.st_mode)) status = ERR_NOT_FOUND;
    else if (st.st_size < 0) status = ERR_INTERNAL;
    else if ((uintmax_t)st.st_size > UINT32_MAX) status = ERR_TOO_LARGE;
    if (status != ERR_OK) { close(fd); return error_response(io, status); }
    uint32_t remaining = (uint32_t)st.st_size;
    int bad = status_byte(io, ERR_OK) != 0;
    if (!bad) bad = number(io, remaining) != 0;
    unsigned char buffer[16384];
    while (!bad && remaining) {
        size_t want = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        ssize_t got = read(fd, buffer, want);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { bad = 1; break; }
        bad = io->write_all(io->state, buffer, (size_t)got) != 0;
        remaining -= (uint32_t)got;
    }
    if (close(fd) < 0) bad = 1;
    return bad ? failed(io) : (server_read_result_t){ERR_OK, 1};
}
