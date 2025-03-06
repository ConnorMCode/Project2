#include <stdio.h>
#include <syscall.h>

int main (int argc, char **argv)
{

  printf("hellooooo");
  
  int i;

  printf("Address of argc: %p\n", (void*)&argc);

  printf("Address of argv: %p\n", (void*)&argv);

  printf("found %d at argc\n", argc);

  printf("found %s at argv[0]\n", argv[0]);

  printf("found %s at argv[1]\n", argv[1]);
  
  printf("got here, found %d at argc and %s at argv[0]\n", argc, argv[0]);
  
  for (i = 0; i < argc; i++)
    printf ("%s ", argv[i]);
  printf ("\n");

  return EXIT_SUCCESS;
  
}
