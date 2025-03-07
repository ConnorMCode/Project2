#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
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

void pointer_validate(const void *ptr) {
  if(ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL){
    return;
  } else {
    exit(-1);
    return;
  }
}

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  pointer_validate(f->esp);

  int *ptr = (int *)f->esp;

  int syscall_number = *ptr;

  switch (syscall_number) {
  case SYS_EXIT:
    pointer_validate(ptr+1);
    exit(*(ptr+1));
    break;

  case SYS_OPEN:
    pointer_validate(ptr+1);
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
  printf("%s: exited with %d\n", thread_current()->name, status);
  thread_exit();
}

int open(const char *file) {
  
  if (file == NULL){
    return(-1);
  }

  struct file *f = filesys_open (file);

  if(f == NULL){
    return(-1);
  }else{
    struct file_struct *fs = malloc(sizeof(struct file_struct));
    fs->ptr = f;
    fs->fd = thread_current()->free_fd;
    thread_current()->free_fd++;
    list_push_back(&thread_current()->files, &fs->file_elem);
    return fs->fd;
  }
  
}

int write(int fd, const void *buffer, unsigned size) {
  pointer_validate(buffer);

  if (fd == 1) {
    putbuf((char *)buffer, size);
    return size;
  }

  //only worried about writing to output
  return -1;
}

void close(int fd_){

  struct list_elem *hold;

  struct file_struct *f;

  if(list_empty(&thread_current()->files)){
    return;
  }

  for (hold = list_front(&thread_current()->files); hold != NULL; hold = hold->next){
    f = list_entry (hold, struct file_struct, file_elem);
    if (f->fd == fd_){
      file_close(f->ptr);
      list_remove(&f->file_elem);
      free(f);
      return;
    }
  }

  return;
}

