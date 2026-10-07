#include "protocol.h"
#include "server.h"

#include <openssl/ssl.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

/* read_fully is a utility function that takes an open SSL connection, and reads the specified amount of 
 * data from the socket into a buffer, returning once all data is consumed.  On errors reading, -1 is returned.
 * If less data is read than was requested, -2 is returned. */
int read_fully(SSL* ssl, void* buf, size_t len, int timeout_sec) {

    fd_set fds;
    struct timeval tv;
    size_t total = 0;
    
    while (total < len) {
	/* Block, with a timeout, on reading until data has arrived. The timeout is provided by the select() system call. */    
        FD_ZERO(&fds);
        FD_SET(SSL_get_fd(ssl), &fds);
        
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        
        int ret = select(SSL_get_fd(ssl) + 1, &fds, NULL, NULL, &tv);
	/* The select call failed for some reason.  Indicate the failure. */
        if (ret < 0) {
            return -1;
        }
	/* select succeeded, but no data is available, even though we need more.  Return a failure. */
        if (ret == 0) {
            return -2;
        }
        
	/* Read up to the amount of data requested. */
        int n = SSL_read(ssl, (char*)buf + total, len - total);
        if (n <= 0) {
            return -1;
        }
        
        total += n;
    }
    
    return 0;
}

/**
 * write_fully is a helper function that writes the specified number of bytes from the buffer to the indicated
 * SSL object, repeating the write if needed. */
int write_fully(SSL* ssl, const void* buf, size_t len) {

    size_t total = 0;
    while (total < len) {
        int n = SSL_write(ssl, (const char*)buf + total, len - total);
        if (n <= 0) {
            return -1;
        }
        total += n;
    }
    return 0;
}

/* Write an error response to the provided SSL context. */
int send_error(SSL* ssl, error_code_t err) {
    return write_fully(ssl, &err, 1);
}

/* validate_filename takes a filename, and ensures that it meets basic sanity requirements. */
int validate_filename(const char* filename) {
    /* Reject any NULL filenames. */
    if (!filename) {
        return 0;
    }
    
    /* Ensure the filename isn't empty, and that it is within the specified length. */
    size_t len = strlen(filename);
    if (len == 0 || len > MAX_FILENAME_LEN) {
        return 0;
    }
    
    /* Forward slashes are disallowed to prevent directory traversal. */
    for (size_t i = 0; i < len; i++) {
        if (filename[i] == '/') {
            return 0;
        }
    }
    
    /* Similarly, '.' and '..' are illegal filenames. */
    if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
        return 0;
    }
    
    return 1;
}

/* get_user_dir takes the specified username and root directory of the service, and returns
 * the full path to the user's directory. */
char* get_user_dir(const char* username, const char* data_dir) {
    size_t len = strlen(data_dir) + 1 + strlen(username) + 1;
    char* dir = malloc(len);
    if (!dir) {
        return NULL;
    }
    snprintf(dir, len, "%s/%s", data_dir, username);
    return dir;
}
