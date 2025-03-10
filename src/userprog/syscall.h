#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdint.h>
#include <list.h>
#include <stdlib.h>
void syscall_init (void);

struct file_struct {
  struct list_elem file_elem;
  struct file *ptr;
  int fd;
  const char *name;
};

struct file_struct *find_file(int fd);

void pointer_validate(const void *ptr);

void exit(int status);
int read(int fd, const void *buffer, unsigned size);
int open(const char *file);
int write(int fd, const void *buffer, unsigned size);
int exec_func(char *file_name);
void close(int fd_);
int symlink(const char *target, const char *linkpath);

#endif /* userprog/syscall.h */
