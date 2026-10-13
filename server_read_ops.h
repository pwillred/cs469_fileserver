#ifndef SERVER_READ_OPS_H
#define SERVER_READ_OPS_H
#include "protocol.h"
#include <stddef.h>

#define SERVER_READ_LIST_MAX 10000
/* Borrowed immutable configuration; administrator-controlled root and DB paths.
 * No provisioning, peer access, shared handles or role decisions. */
typedef struct { const char *data_dir; const char *auth_db_path; } server_read_context_t;
/* Exact I/O: return 0 only after transferring all bytes, otherwise -1.
 * abort must terminate transport without sending more application bytes.
 * Callbacks must bound blocking and handle their transport's signal policy. */
typedef struct {
    void *state;
    int (*read_exact)(void *, void *, size_t);
    int (*write_all)(void *, const void *, size_t);
    void (*abort)(void *);
} server_read_io_t;
/* complete=1 means the entire response (including an error status) was sent.
 * complete=0 means transport was aborted; status is the local failure reason.
 * Handlers OWN all status/payload output. Never append a wrapper/final status.
 * Dispatcher consumes only the literal verb first. One request per connection;
 * caller closes/frees transport after return, and logs incomplete results without
 * credentials. Separate connection/state per concurrent invocation. */
typedef struct { error_code_t status; int complete; } server_read_result_t;
server_read_result_t server_handle_list(const server_read_io_t *, const server_read_context_t *);
server_read_result_t server_handle_download(const server_read_io_t *, const server_read_context_t *);
#endif
