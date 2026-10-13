#define _DARWIN_C_SOURCE
#include "../server_read_ops.h"
#include "../password_db.h"
#include "server_read_faults.h"
#include <openssl/crypto.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL read line %d\n", __LINE__); exit(1); } } while (0)
/* Substitutions affect only server_read_ops' dedicated test object. Actual auth
 * and DB implementations remain linked. Every handler exit proves full erasure. */
static int cleanses, read_mode;
void read_test_cleanse(void *p, size_t n) {
    CHECK(n == 65); OPENSSL_cleanse(p, n);
    for (size_t i = 0; i < n; ++i) CHECK(((unsigned char *)p)[i] == 0);
    ++cleanses;
}
ssize_t read_test_read(int fd, void *p, size_t n) {
    if (read_mode == 1) { errno = EIO; return -1; }
    if (read_mode == 2) return 0;
    if (read_mode == 3) { read_mode = 4; errno = EINTR; return -1; }
    return read(fd, p, read_mode == 4 && n > 1 ? 1 : n);
}
struct memory {
    const unsigned char *input; size_t size, pos;
    unsigned char output[1024]; size_t used;
    int fail_write, writes, aborted;
};
static int get(void *p, void *out, size_t n) {
    struct memory *m = p;
    if (n > m->size - m->pos) return -1;
    memcpy(out, m->input + m->pos, n); m->pos += n; return 0;
}
static int put(void *p, const void *in, size_t n) {
    struct memory *m = p;
    if (++m->writes == m->fail_write) return -1;
    CHECK(n <= sizeof(m->output) - m->used);
    memcpy(m->output + m->used, in, n); m->used += n; return 0;
}
static void stop(void *p) { ((struct memory *)p)->aborted++; }
static int cases;
static void run(server_read_context_t *ctx, int download, const void *input, size_t n,
                int write_fail, int expected, int complete, const void *bytes, size_t length) {
    struct memory m = {.input=input, .size=n, .fail_write=write_fail};
    server_read_io_t io = {&m, get, put, stop};
    int before = cleanses;
    server_read_result_t r = download ? server_handle_download(&io, ctx) : server_handle_list(&io, ctx);
    CHECK(r.status == (error_code_t)expected && r.complete == complete);
    CHECK(cleanses == before + 1 && m.aborted == !complete);
    CHECK(m.used == length && (!length || memcmp(bytes, m.output, length) == 0));
    ++cases;
}
int main(void) {
    char root[] = "/tmp/cs469-read-XXXXXX"; CHECK(mkdtemp(root));
    char dbpath[256], dir[256], path[256];
    snprintf(dbpath, sizeof(dbpath), "%s/auth.db", root);
    snprintf(dir, sizeof(dir), "%s/alice", root);
    snprintf(path, sizeof(path), "%s/alice/file", root);
    password_db_t *db = NULL; CHECK(password_db_open(dbpath, &db) == 0);
    CHECK(password_db_init_schema(db) == 0 && password_db_add_user(db, "alice", "secret") == 0);
    password_db_close(db);
    CHECK(mkdir(dir, 0700) == 0);
    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0600); CHECK(fd >= 0);
    CHECK(write(fd, "payload", 7) == 7 && close(fd) == 0);
    server_read_context_t ctx = {root, dbpath};
    const char request[] = "alice\0secret\0file";
    const unsigned char full[] = {0,0,0,0,7,'p','a','y','l','o','a','d'};
    run(&ctx, 1, request, sizeof(request), 0, 0, 1, full, sizeof(full));
    read_mode = 1; run(&ctx, 1, request, sizeof(request), 0, 7, 0, full, 5);
    read_mode = 2; run(&ctx, 1, request, sizeof(request), 0, 7, 0, full, 5);
    read_mode = 3; run(&ctx, 1, request, sizeof(request), 0, 0, 1, full, sizeof(full));
    read_mode = 0;
    for (int i = 1; i <= 3; ++i)
        run(&ctx, 1, request, sizeof(request), i, 7, 0, full, i == 1 ? 0 : i == 2 ? 1 : 5);
    const char list[] = "alice\0secret";
    const unsigned char listing[] = {0,0,0,0,1,'f','i','l','e',0};
    for (int i = 1; i <= 3; ++i)
        run(&ctx, 0, list, sizeof(list), i, 7, 0, listing, i == 1 ? 0 : i == 2 ? 1 : 5);
    /* All possible credential/filename prefix EOFs, including password tails. */
    unsigned char bad = 4;
    for (size_t i = 0; i < sizeof(request); ++i)
        run(&ctx, 1, request, i, 0, 4, 1, &bad, 1);
    const char wrong[] = "alice\0wrong\0file"; unsigned char auth = 1;
    run(&ctx, 1, wrong, sizeof(wrong), 0, 1, 1, &auth, 1);
    const char invalid[] = "alice\0secret\0../x";
    run(&ctx, 1, invalid, sizeof(invalid), 0, 4, 1, &bad, 1);
    ctx.auth_db_path = "/nonexistent-cs469-read-test.db"; unsigned char internal = 7;
    run(&ctx, 0, list, sizeof(list), 0, 7, 1, &internal, 1);
    CHECK(unlink(path) == 0 && rmdir(dir) == 0 && unlink(dbpath) == 0 && rmdir(root) == 0);
    printf("PASS: %d read handler fault/cleanup cases (read EIO/EOF/EINTR/short reads, write failures, no extra status)\n", cases);
}
