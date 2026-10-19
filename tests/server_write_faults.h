#ifndef SERVER_WRITE_FAULTS_H
#define SERVER_WRITE_FAULTS_H
#include <stdio.h>
#include <sys/types.h>
size_t fault_fwrite(const void *, size_t, size_t, FILE *);
int fault_ferror(FILE *);
int fault_fclose(FILE *);
ssize_t fault_write(int, const void *, size_t);
#endif
