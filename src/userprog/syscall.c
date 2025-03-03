#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  if (!is_valid_user_pointer(f->esp)){
    exit(-1);
  }

  int *ptr = (int *)f->esp

  int syscall_number = *ptr;

  switch (syscall_number) {
  case SYS_EXIT:
    if(pointer_validate
    exit(*(ptr+1));
    break;
  }
}

static bool pointer_validate(const void *ptr) {
  bool validate = (ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL);
  return validate;
}

