#define _FCNTL_H
#include <linux/stat.h>
#include <stddef.h>
#include <sys/types.h>
#include <bits/fcntl.h>
#include <bits/stat.h>
#include <stdio.h>
#include <signal.h>

static int  write(int fd, const void *buf, size_t count) {
  register int8_t     rax asm("rax") = 1;
  register int        rdi asm("rdi") = fd;
  register const void *rsi asm("rsi") = buf;
  register size_t     rdx asm("rdx") = count;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  open(const char *pathname, int flags, int mode) {
  register int8_t     rax asm("rax") = 2;
  register const char *rdi asm("rdi") = pathname;
  register int        rsi asm("rsi") = flags;
  register int        rdx asm("rdx") = mode;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  close(int fd) {
  register int8_t       rax asm("rax") = 3;
  register unsigned int rdi asm("rdi") = fd;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  fstat(int fd, struct stat *statbuf) {
  register int8_t       rax asm("rax") = 5;
  register unsigned int rdi asm("rdi") = fd;
  register struct stat  *rsi asm("rsi") = statbuf;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static void *memcpy(void *dest, const void *src, size_t n) {
  char  *result;

  result = dest;
  while (n-- > 0) {
    result[n] = ((char *)src)[n];
    n -= 1;
  }
  return (dest);
}

static char *strcat(char *dest, const char *src) {
  int i;
  int j;

  i = 0;
  while (dest[i])
    i += 1;
  j = 0;
  while (src[j]) {
    dest[i] = src[j];
    i += 1;
    j += 1;
  }
  dest[i] = '\0';
  return (dest);
}

static size_t strlen(const char *s) {
  size_t  i;

  i = 0;
  while (s[i])
    i += 1;
  return (i);
}

int strcmp(const char *s1, const char *s2) {
  size_t  i;

  i = 0;
  while (s1[i] && s2[i]) {
    if (s1[i] != s2[i])
      return (s1[i] - s2[i]);
    i += 1;
  }
  return (s1[i] - s2[i]);
}

void  *memmove(void *dest, const void *src, size_t n) {
  size_t  i;

  i = 0;
  if (src >= dest)
    memcpy(dest, src, n);
  else {
    i += n - 1;
    while (n-- > 0) {
      ((char *)dest)[i] = ((char *)src)[i];
      i -= 1;
    }
  }
  return (dest);
}

int   main(void) {
  int   fd;
  char  helloWorld[] = "HelloWorld";

  fd = open(helloWorld, O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  write(fd, helloWorld, 10);
  close(fd);
  return (0);
}
