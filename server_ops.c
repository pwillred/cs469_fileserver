#include "password.h"
#include "protocol.h"
#include "server.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* handle_client is a function that can be passed into pthread_create.  It sets up the SSL connection
 * for the incoming request, and dispatches the request to the appropriate handle, cleaning up system
 * resources once work is done. */ 
void* handle_client(void* arg) {
   
    /* Pull the context out of the supplied argument. */	
    client_context_t *ctx = (client_context_t*) arg;

    /* Create a new SSL structure for a specific connection. */
    SSL* ssl = SSL_new(ctx->ssl_ctx);
    SSL_set_fd(ssl, ctx->sock);
    
    /* Wait for the client to start the TLS/SSL handshake. */
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Failed to establish TLS connection\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(ctx->sock);
        free(ctx);
        return NULL;
    }
    
    /* Dispatch the request, optionally handling any errors received. */
    error_code_t err = handle_request(ssl, ctx->config);
    send_error(ssl, err);
    
    /* Clean up and return. */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(ctx->sock);
    
    free(ctx);
    
    return NULL;
}

/* handle_request dispatches a request to the handler that can service the request. */
error_code_t handle_request(SSL* ssl, const server_config_t* config) {
    /* Read the command off of the stream. */	
    char cmd[9];
    int ret = read_fully(ssl, cmd, 8, config->timeout_sec);
    if (ret < 0) {
        return ERR_BAD_REQUEST;
    }
    cmd[8] = '\0';
    
    
    if (strncmp(cmd, LIST_CMD, LIST_CMD_LEN) == 0) {
        return ERR_OK; //stub
    } else if (strncmp(cmd, UPLOAD_CMD, UPLOAD_CMD_LEN) == 0) {
        return handle_upload(ssl, config);
    } else if (strncmp(cmd, DOWNLOAD_CMD, DOWNLOAD_CMD_LEN) == 0) {
        return ERR_OK; //stub
    } else if (strncmp(cmd, DELETE_CMD, DELETE_CMD_LEN) == 0) {
        return handle_delete(ssl, config);
    }
    
    return ERR_BAD_REQUEST; // unrecognized command
}



/* handle_upload handles the UPLOAD commands for an open connection. */
error_code_t handle_upload(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    uint32_t size;

    /* Check password... */
    error_code_t err = read_and_verify_credentials(ssl, config, username);
    if (err != ERR_OK) {
        return err;
    }

    /* ...then the filename and length. */
    err = read_filename(ssl, config, filename);
    if (err != ERR_OK) {
    	return err;
    }
    
    int ret = read_fully(ssl, &size, 4, config->timeout_sec);
    if (ret < 0) {
        return ERR_BAD_REQUEST;
    }
    size = ntohl(size);
    
    if (size > MAX_FILE_SIZE) {
        return ERR_TOO_LARGE;
    }
    
    /* Find the user's directory, the build the new filename. */
    char* user_dir = get_user_dir(username, config->data_dir);
    if (!user_dir) {
        return ERR_INTERNAL;
    }
    
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/.temp_%s", user_dir, filename);
    
    /* open the file to upload. */
    FILE* f = fopen(temp_path, "wb");
    if (!f) {
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    /* Allocate an 8Kb buffer on the heap for the upload. */
    char* buf = malloc(8192);
    if (!buf) {
        fclose(f);
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    /* Read the file, one buffer at a time. */
    size_t remaining = size;
    while (remaining > 0) {
        size_t to_read = remaining < 8192 ? remaining : 8192;
        ret = read_fully(ssl, buf, to_read, config->timeout_sec);
        if (ret < 0) {
            free(buf);
            fclose(f);
            unlink(temp_path);
            free(user_dir);
            return ERR_BAD_REQUEST;
        }
	/* Write data out to the file. */
        fwrite(buf, 1, to_read, f);
        remaining -= to_read;
    }
    
    fclose(f);
    free(buf);
    
    char final_path[512];
    snprintf(final_path, sizeof(final_path), "%s/%s", user_dir, filename);
    
    /* TODO prepare/commit flow goes here.  This is stubbed out. */
    if (rename(temp_path, final_path) < 0) {
        unlink(temp_path);
        free(user_dir);
        return ERR_INTERNAL;
    }
    
    free(user_dir);
    return ERR_OK;
}

/* handle_delete processes the DELETE command, removing a file from a user's home directory. */
error_code_t handle_delete(SSL* ssl, const server_config_t* config) {
    char username[MAX_USERNAME_LEN + 1];
    char filename[MAX_FILENAME_LEN + 1];
    
    /* verify the usernmae and password, then the filename. */
    error_code_t err = read_and_verify_credentials(ssl, config, username);
    if (err != ERR_OK) {
        return err;
    }

    err = read_filename(ssl, config, filename);
    if (err != ERR_OK) {
    	return err;
    }
     
    char* user_dir = get_user_dir(username, config->data_dir);
    if (!user_dir) {
        return ERR_INTERNAL;
    }
    
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s", user_dir, filename);
    
    if (unlink(file_path) < 0) {
        free(user_dir);
        return ERR_NOT_FOUND;
    }
    
    free(user_dir);
    return ERR_OK;
}


error_code_t read_and_verify_credentials(SSL* ssl, const server_config_t* config, char *username) {
    char password[MAX_PASSWORD_LEN + 1];
    int ret = read_fully(ssl, username, MAX_USERNAME_LEN + 1, config->timeout_sec);
    if (ret < 0) {
        return ERR_BAD_REQUEST;
    }
    
    ret = read_fully(ssl, password, MAX_PASSWORD_LEN + 1, config->timeout_sec);
    if (ret < 0) {
        return ERR_BAD_REQUEST;
    }
    
    if (!verify_password(username, password)) {
        return ERR_AUTH_FAILED;
    }
    
   
    return ERR_OK;
}

error_code_t read_filename(SSL *ssl, const server_config_t *config, char *filename) {
   if (filename) {
        int ret = read_fully(ssl, filename, MAX_FILENAME_LEN + 1, config->timeout_sec);
        if (ret < 0) {
            return ERR_BAD_REQUEST;
        }
        
        if (!validate_filename(filename)) {
            return ERR_BAD_REQUEST;
        }
    }
    return ERR_OK;
}


