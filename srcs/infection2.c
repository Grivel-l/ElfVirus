#include <stddef.h>
#include <sys/types.h>

static int   myWrite(int fd, const void *buf, size_t count) {
  register int8_t     rax asm("rax") = 1;
  register int        rdi asm("rdi") = fd;
  register const void *rsi asm("rsi") = buf;
  register size_t     rdx asm("rdx") = count;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

int   infection(void) {
  char  helloWorld[] = "HelloWorld\n";

  myWrite(1, helloWorld, 11);
  return (0);
}
