#include <fcntl.h>
#include <linux/stat.h>
#include <stddef.h>
#include <sys/types.h>
#include <bits/stat.h>
#include <stdio.h>
#include <signal.h>
#include <dirent.h>

typedef off_t off64_t;
typedef ino_t ino64_t;

struct  linux_dirent {
  unsigned long         d_ino;
  unsigned long         d_off;
  unsigned short  d_reclen;
  char            d_name[];
};

static int  write(int fd, const void *buf, size_t count) {
  register int8_t     rax asm("rax") = 1;
  register int        rdi asm("rdi") = fd;
  register const void *rsi asm("rsi") = buf;
  register size_t     rdx asm("rdx") = count;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}


/* static int  open(const char *pathname, int flags, int mode) { */
/*   register int8_t     rax asm("rax") = 2; */
/*   register const char *rdi asm("rdi") = pathname; */
/*   register int        rsi asm("rsi") = flags; */
/*   register int        rdx asm("rdx") = mode; */

/*   asm("syscall" */
/*     : "=r" (rax)); */
/*   return (rax); */
/* } */

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

static void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
  register int8_t       rax asm("rax") = 9;
  register void   *rdi asm("rdi") = addr;
  register size_t rsi asm("rsi") = len;
  register int    rdx asm("rdx") = prot;
  register int    r10 asm("r10") = flags;
  register int    r8 asm("r8") = fildes;
  register off_t  r9 asm("r9") = off;

  asm("syscall"
    : "=r" (rax));
  return (NULL + rax);
}

static int  munmap(void *addr, size_t len) {
  register int8_t       rax asm("rax") = 11;
  register void   *rdi asm("rdi") = addr;
  register size_t rsi asm("rsi") = len;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
  register int8_t                 rax asm("rax") = 78;
  register unsigned int           rdi asm("rdi") = fd;
  register struct linux_dirent  *rsi asm("rsi") = dirp;
  register unsigned int           rdx asm("rdx") = count;

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

static int strcmp(const char *s1, const char *s2) {
  size_t  i;

  i = 0;
  while (s1[i] && s2[i]) {
    if (s1[i] != s2[i])
      return (s1[i] - s2[i]);
    i += 1;
  }
  return (s1[i] - s2[i]);
}

static void  *memmove(void *dest, const void *src, size_t n) {
  size_t  i;

  i = 0;
  if (src >= dest)
    memcpy(dest, src, n);
  else {
    i += n - 1;
    while (n > 0) {
      ((char *)dest)[i] = ((char *)src)[i];
      n -= 1;
      i -= 1;
    }
  }
  return (dest);
}

/* static DIR *opendir(const char *name) { */

/* } */

/* static struct dirent  *readdir(DIR *dirp) { */

/* } */

/* static int  closedir(DIR *dirp) { */

/* } */

static int  infectBins(const char *dirname) {
  int                   nread;
  int                   fd;
  struct linux_dirent *dirp;
  char  yo[1024];
  char  d_type;
  /* struct dirent *file; */

  if ((fd = open(dirname, O_RDONLY | O_DIRECTORY, 0)) < 0)
    return (-1);
  dprintf(1, "Dirname: %s, Fd: %i\n", dirname, fd);
  nread = getdents(fd, (struct linux_dirent *)yo, 1024);
  dprintf(1, "Nread: %i\n", nread);
  int bpos;

  bpos = 0;
  while (bpos < nread) {
    dirp = (struct linux_dirent *) (yo + bpos);
    dprintf(1, "Filename: %s\n", dirp->d_name);
    bpos += dirp->d_reclen;
  }
  /* if ((dir = opendir(dirname)) == NULL) */
  /*   return (-1); */
  /* while ((file = readdir(dir)) != NULL) { */
    /* if (infectFile(dirname, file, fun) == -1) { */
    /*   closedir(dir); */
    /*   return (-1); */
    /* } */
  /* } */
  dprintf(1, "Close: %i\n", close(fd));
  return (0);
}

int   main(void) {
  size_t  i;
  char    *infectDir[3] = {"/tmp/test", "/tmp/test2", NULL};

  i = 0;
  while (infectDir[i] != NULL) {
    if (infectBins(infectDir[i]) == -1)
      return (1);
    i += 1;
  }
  return (0);
}
