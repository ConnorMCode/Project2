#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void syscall_init (void);

void pointer_validate(const void *ptr);

void exit(int status);
int read(int fd, const void *buffer, unsigned size);
int open(const char *file);
int write(int fd, const void *buffer, unsigned size);
void close(int fd_);
int symlink(char *target, char *linkpath);

#endif /* userprog/syscall.h */
