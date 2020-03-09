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

struct  bfile {
  off_t       size;
  Elf64_Ehdr  *header;
};

#endif
