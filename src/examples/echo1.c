 #include <stdio.h>
#include <syscall.h>

int main (void)
{
  int fd;

  fd = open("test.txt");
  if (fd < 0){
    printf("FAIL: Could not open test.txt\n");
  } else {
    printf("PASS: Opened test.txt with fd: %d\n", fd);
  }

  if (fd > 1){
    close(fd);

    printf("PASS: Closed test.txt\n");

    close(fd);
    printf("PASS: Tried closing again");
  }

  fd = open("non-existent.txt");
  if (fd < 0){
    printf("PASS: Opening non existent file failed as expected");
  } else {
    printf("FAIL: Opened non_existent.txt, shouldn't happen");
  }

  return EXIT_SUCCESS;
  
}
