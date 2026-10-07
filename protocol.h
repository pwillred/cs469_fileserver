/**
 * CS 469
 * Fedil Grogan & Brian Leake
 *
 * Protocol.h provides #defines used for implementing the protocol described for this service.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* Error codes */
typedef enum {
    ERR_OK              = 0,
    ERR_AUTH_FAILED     = 1,
    ERR_NOT_FOUND       = 2,
    ERR_EXISTS          = 3,
    ERR_BAD_REQUEST     = 4,
    ERR_TOO_LARGE       = 5,
    ERR_REPLICATION_FAILED = 6,
    ERR_INTERNAL        = 7
} error_code_t;

/* Operation verbs */
#define LIST_CMD     "LIST"
#define UPLOAD_CMD   "UPLOAD"
#define DOWNLOAD_CMD "DOWNLOAD"
#define DELETE_CMD   "DELETE"

/* Length of the commands used in the protocol in bytes. */
#define LIST_CMD_LEN     4
#define UPLOAD_CMD_LEN   6
#define DOWNLOAD_CMD_LEN 8
#define DELETE_CMD_LEN   6

/* Maximum field sizes in bytes */
#define MAX_USERNAME_LEN    64
#define MAX_PASSWORD_LEN    64
#define MAX_FILENAME_LEN    256


/* Replication prepare/commit bytes */
#define PREPARE_OK    0
#define COMMIT        0
#define ABORT         1


/* Replication header sizes (without password) */
#define UPLOAD_REP_HEADER_LEN (UPLOAD_CMD_LEN + MAX_USERNAME_LEN + 4 + MAX_FILENAME_LEN + 2)
#define DELETE_REP_HEADER_LEN (DELETE_CMD_LEN + MAX_USERNAME_LEN + MAX_FILENAME_LEN + 2)

#define MAX_FILE_SIZE (1024 * 1024 * 1024)

#endif /* PROTOCOL_H */
