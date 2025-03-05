#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

static bool pointer_validate(const void *ptr) {
  bool validate = (ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL);
  return validate;
}

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  if (!pointer_validate(f->esp)){
    exit(-1);
  }

  int *ptr = (int *)f->esp;

  int syscall_number = *ptr;

  switch (syscall_number) {
  case SYS_EXIT:
    if (!pointer_validate(ptr+1)){
      exit(-1);
    }
    exit(*(ptr+1));
    break;

  case SYS_WRITE:
    if (!pointer_validate(ptr+1) || !pointer_validate(ptr+2) || !pointer_validate(ptr+3)){
      exit(-1);
    }
    f->eax = write(*(ptr+1), (void *)*(ptr+2), *(unsigned *)(ptr+3));
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

int write(int fd, const void *buffer, unsigned size) {
  if(!pointer_validate(buffer)){
    exit(-1);
  }

  if (fd == 1) {
    putbuf((char *)buffer, size);
    return size;
  }

  //only worried about writing to output
  return -1;
}



