#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

struct file_struct {
  struct list_elem file_elem;
  struct file *ptr;
  int fd;
};

struct lock file_lock;

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
  
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  pointer_validate((const void *)f->esp);

  int *ptr = (int *)f->esp;
  
  int syscall_number = *ptr;

  switch (syscall_number) {
  case SYS_EXIT:
    pointer_validate(ptr+1);
    exit(*(ptr+1));
    break;

  case SYS_CREATE:
    pointer_validate(ptr+1);
    pointer_validate(ptr+2);
    pointer_validate(*(ptr+1));
    lock_acquire(&file_lock);

    if((const char *)*(ptr+1) == NULL){
      lock_release(&file_lock);
      exit(-1);
      break;
    }

    if((const char *)*(ptr+1) == '\0'){
      f->eax = 0;
      lock_release(&file_lock);
      exit(-1);
      break;
    }
    
    f->eax = filesys_create(*(ptr+1), *(ptr+2));
    lock_release(&file_lock);
    break;
    
  case SYS_OPEN:
    pointer_validate(ptr+1);
    pointer_validate(*(ptr+1));
    f->eax = open((const char *)*(ptr+1));
    break;

  case SYS_WRITE:
    pointer_validate(ptr+1);
    pointer_validate(ptr+2);
    pointer_validate(ptr+3);
    f->eax = write(*(ptr+1), (void *)*(ptr+2), *(unsigned *)(ptr+3));
    break;

  case SYS_CLOSE:
    pointer_validate(ptr+1);
    close(*(ptr+1));
    break;
    
  default:
    printf("Unwritten syscall: %d\n", syscall_number);
    exit(-1);
  }
}

void exit(int status){
  thread_current()->exit_code = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

int open(const char *file) {

  lock_acquire(&file_lock);
  
  if (file == NULL){
    lock_release(&file_lock);
    return(-1);
  }

  struct file *f = filesys_open (file);

  if(f == NULL){
    lock_release(&file_lock);
    return(-1);
  }else{
    struct file_struct *fs = malloc(sizeof(struct file_struct));
    fs->ptr = f;
    fs->fd = thread_current()->free_fd;
    thread_current()->free_fd++;
    list_push_back(&thread_current()->files, &fs->file_elem);
    lock_release(&file_lock);
    return fs->fd;
  }
  
}

int write(int fd, const void *buffer, unsigned size) {

  lock_acquire(&file_lock);
  pointer_validate(buffer);

  if (fd == 1) {
    putbuf((char *)buffer, size);
    lock_release(&file_lock);
    return size;
  }

  //only worried about writing to output
  lock_release(&file_lock);
  return -1;
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
      free(f);
      lock_release(&file_lock);
      return;
    }
  }

  lock_release(&file_lock);
  return;
}

