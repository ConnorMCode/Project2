#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include <string.h>
#include "devices/block.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;

struct list symlink_list;

struct file_struct *find_file(int fd, struct list *files){
  struct list_elem *e;

  for(e = list_begin(files); e != list_end(files); e = list_next(e)){
    struct file_struct *fs = list_entry(e, struct file_struct, file_elem);
    if (fs->fd == fd){
      return fs;
    }
  }
  return NULL;
}

struct file_struct *check_symlink(const char *path){
  struct list_elem *e;
  for (e = list_begin(&symlink_list); e != list_end(&symlink_list); e = list_next(e)){
    struct file_struct *fs = list_entry(e, struct file_struct, file_elem);
    if (strcmp(fs->name, path) == 0){
      return fs;
    }
  }
  return NULL;
}

void pointer_validate(const void *ptr) {
  
  if (ptr == NULL || !is_user_vaddr(ptr) || !is_user_vaddr((char *)ptr+3) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL ||
      pagedir_get_page(thread_current()->pagedir, (char *)ptr + 3) == NULL){
    exit(-1);
    return;
  }

  return;
}

void syscall_init (void)
{
  lock_init(&file_lock);
  list_init(&symlink_list);
  
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  pointer_validate((const void *)f->esp);
  
  int *ptr = (int *)f->esp;
  
  int syscall_number = *ptr;

  switch (syscall_number) {

  case SYS_HALT:
    shutdown_power_off();
    
  case SYS_EXIT:
    pointer_validate(ptr+1);
    exit(*(ptr+1));
    break;

  case SYS_EXEC:
    pointer_validate(ptr+1);
    pointer_validate((const void *)*(ptr+1));
    f->eax = exec_func((char *)*(ptr+1));
    break;

  case SYS_WAIT:
    pointer_validate(ptr+1);
    f->eax = process_wait(*(ptr+1));
    break;

  case SYS_CREATE:
    pointer_validate(ptr+1);
    pointer_validate(ptr+2);
    pointer_validate((const void *)*(ptr+1));
    lock_acquire(&file_lock);

    if((const char *)*(ptr+1) == NULL){
      lock_release(&file_lock);
      exit(-1);
      break;
    }

    if((const char *)*(ptr+1) == NULL){
      f->eax = 0;
      lock_release(&file_lock);
      exit(-1);
      break;
    }
    
    f->eax = filesys_create((const char *)*(ptr+1), *(ptr+2));
    lock_release(&file_lock);
    break;

  case SYS_REMOVE:
    pointer_validate(ptr+1);
    pointer_validate((const void *)*(ptr+1));
    lock_acquire(&file_lock);
    bool remove_result = filesys_remove((const char *)*(ptr+1));
    f->eax = remove_result;
    lock_release(&file_lock);
    break;
    
  case SYS_OPEN:
    pointer_validate(ptr+1);
    pointer_validate((const void *)*(ptr+1));
    f->eax = open((const char *)*(ptr+1));
    break;
    
  case SYS_FILESIZE:
    pointer_validate(ptr+1);
    lock_acquire(&file_lock);
    f->eax = file_length(find_file(*(ptr+1), &thread_current()->files)->ptr);
    lock_release(&file_lock);
    break;
    
  case SYS_READ:
    pointer_validate(ptr+1);
    pointer_validate(ptr+2);
    pointer_validate(ptr+3);
    pointer_validate((const void *)*(ptr+2));
    f->eax = read(*(ptr+1), (void *)*(ptr+2), *(unsigned *)(ptr+3));
    break;
    
  case SYS_WRITE:
    pointer_validate(ptr+1);
    pointer_validate(ptr+2);
    pointer_validate(ptr+3);
    f->eax = write(*(ptr+1), (void *)*(ptr+2), *(unsigned *)(ptr+3));
    break;

  case SYS_SEEK:
    pointer_validate(ptr+1);
    pointer_validate(ptr+2);

    int fd_seek = *(int *)(ptr+1);
    unsigned position = *(unsigned *)(ptr+2);

    lock_acquire(&file_lock);
    struct file_struct *fs = find_file(fd_seek, &thread_current()->files);
    if (fs == NULL){
      lock_release(&file_lock);
      break;
    }

    file_seek(fs->ptr, position);
    lock_release(&file_lock);
    break;

  case SYS_TELL:
    pointer_validate(ptr+1);
    int fd_tell = *(int *)(ptr+1);
    lock_acquire(&file_lock);
    f->eax = file_tell(find_file(fd_tell, &thread_current()->files)->ptr);
    lock_release(&file_lock);
    break;

  case SYS_CLOSE:
    pointer_validate(ptr+1);
    close(*(ptr+1));
    break;

  case SYS_SYMLINK:
    pointer_validate(ptr+1);
    pointer_validate(ptr+2);

    const char *target = *(const char **)(ptr+1);
    const char *linkpath = *(const char **)(ptr+2);

    f->eax = symlink(target, linkpath);

    break;
    
  default:
    printf("Unwritten syscall: %d\n", syscall_number);
    exit(-1);
  }
}

void exit(int status){
  thread_current()->exit_code = status;

  thread_current()->my_child_struct->exit_code = status;

  printf("%s: exit(%d)\n", thread_current()->name, status);
  
  thread_exit();
}

int exec_func(char *file_name){
  lock_acquire(&file_lock);
  char *fn_copy = palloc_get_page(0);
  strlcpy(fn_copy, file_name, PGSIZE);

  char *saveptr;
  fn_copy = strtok_r(fn_copy, " ", &saveptr);

  struct file *check_file = filesys_open(fn_copy);

  if(check_file == NULL){
    palloc_free_page(fn_copy);
    lock_release(&file_lock);
    return -1;
  }else{
    file_close(check_file);
    palloc_free_page(fn_copy);
    lock_release(&file_lock);
    return process_execute(file_name);
  }
  
}

int open(const char *file) {

  lock_acquire(&file_lock);
  
  if (file == NULL){
    lock_release(&file_lock);
    return(-1);
  }

  struct file_struct *sym_check = check_symlink(file);
  if (sym_check != NULL){
    if(filesys_open(sym_check->target_path) == NULL){
      lock_release(&file_lock);
      return -1;
    }else{
      lock_release(&file_lock);
      return (open(sym_check->target_path));
    }
  }

  struct file *f = filesys_open(file);
  
  if(f == NULL){
    lock_release(&file_lock);
    return(-1);
  }else{
    struct file_struct *fs = palloc_get_page(PAL_ZERO);
    if (fs == NULL) {
      file_close(f);
      lock_release(&file_lock);
      return -1;
    }
    fs->ptr = f;
    fs->name = file;
    fs->fd = thread_current()->free_fd;
    thread_current()->free_fd++;
    list_push_back(&thread_current()->files, &fs->file_elem);
    lock_release(&file_lock);
    return fs->fd;
  }
}

int read(int fd, const void *buffer, unsigned size) {
  lock_acquire(&file_lock);
  
  if (buffer == NULL) {
    lock_release(&file_lock);
    return -1;
  }

  if (fd == 0){
    for(unsigned i = 0; i < size; i++){
      ((char *)buffer)[i] = input_getc();
    }
    lock_release(&file_lock);
    return size;
  }

  struct file_struct *fs = find_file(fd, &thread_current()->files);
  if (fs == NULL){
    lock_release(&file_lock);
    return -1;
  }

  struct file_struct *sym_check = check_symlink(fs->name);
  if (sym_check != NULL){
    if(filesys_open(sym_check->target_path) == NULL){
      lock_release(&file_lock);
      return -1;
    }else{
      fs = find_file(sym_check->fd, &thread_current()->files);
    }
  }

  int bytes_read = file_read(fs->ptr, (void *)buffer, size);
  lock_release(&file_lock);
  return bytes_read;
}

int write(int fd, const void *buffer, unsigned size) {
  
  lock_acquire(&file_lock);
  pointer_validate(buffer);

  if (fd == 1) {
    putbuf((char *)buffer, size);
    lock_release(&file_lock);
    return size;
  }

  struct file_struct *fs = find_file(fd, &thread_current()->files);
  if (fs == NULL) {
    lock_release(&file_lock);
    return -1;
  }

  if(strcmp(thread_current()->name, fs->name) == 0){
    lock_release(&file_lock);
    return 0;
  }

  struct file_struct *sym_check = check_symlink(fs->name);
  if (sym_check != NULL){
    if(filesys_open(sym_check->target_path) == NULL){
      lock_release(&file_lock);
      return -1;
    }else{
      fs = find_file(sym_check->fd, &thread_current()->files);
    }
  }
  
  int bytes_written = file_write(fs->ptr, buffer, size);
  
  lock_release(&file_lock);
  return bytes_written;
}

void close(int fd_){

  struct list_elem *hold;

  struct file_struct *f;

  lock_acquire(&file_lock);
  
  if(list_empty(&thread_current()->files)){
    lock_release(&file_lock);
    return;
  }

  for (hold = list_front(&thread_current()->files); hold != NULL; hold = hold->next){
    f = list_entry (hold, struct file_struct, file_elem);
    if (f->fd == fd_){
      file_close(f->ptr);
      list_remove(&f->file_elem);
      palloc_free_page(f);
      lock_release(&file_lock);
      return;
    }
  }

  lock_release(&file_lock);
  return;
}

int symlink(const char *target, const char *linkpath){
  lock_acquire(&file_lock);

  int fd_hold;

  if (target == NULL || linkpath == NULL){
    lock_release(&file_lock);
    return -1;
  }

  struct file *target_file = filesys_open(target);
  if(target_file == NULL){
    lock_release(&file_lock);
    return -1;
  }

  struct file_struct *target_hold = palloc_get_page(PAL_ZERO);
  if (target_hold == NULL) {
    file_close(target_file);
    lock_release(&file_lock);
    return -1;
  }
  target_hold->ptr = target_file;
  target_hold->name = target;
  target_hold->fd = thread_current()->free_fd;
  fd_hold = target_hold->fd;
  thread_current()->free_fd++;
  list_push_back(&thread_current()->files, &target_hold->file_elem);
  
  file_close(target_file);

  struct file *exists = filesys_open(linkpath);
  if (exists != NULL){
    file_close(exists);
    lock_release(&file_lock);
    return -1;
  }

  if (!filesys_create(linkpath, strlen(target))){
    lock_release(&file_lock);
    return -1;
  }

  struct file *link_file = filesys_open(linkpath);
  if (link_file == NULL){
    lock_release(&file_lock);
    return -1;
  }

  if (file_write(link_file, target, strlen(target)) != (int)strlen(target)){
    file_close(link_file);
    filesys_remove(linkpath);
    lock_release(&file_lock);
    return -1;
  }

  struct file_struct *fs = palloc_get_page(PAL_ZERO);
  if (fs == NULL) {
    file_close(link_file);
    lock_release(&file_lock);
    return -1;
  }
  fs->ptr = link_file;
  fs->target_path = target;
  fs->name = linkpath;
  fs->fd = fd_hold;
  list_push_back(&symlink_list, &fs->file_elem);

  file_close(link_file);
  lock_release(&file_lock);
  return 0;
}
