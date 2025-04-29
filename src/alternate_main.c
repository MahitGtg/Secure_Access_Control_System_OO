
#include <stdio.h>

#ifdef ALTERNATE_MAIN
int main(int argc, char *argv[]) {
  printf("an alternative implementation of main\n"); 
  return 0;
}
#endif

