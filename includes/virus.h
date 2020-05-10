#ifndef VIRUS_H
# define VIRUS_H

# include <stdio.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
# include <elf.h>
# include <string.h>
# include <stdlib.h>

#define PAYLOAD_EP "entry_point"

typedef int (*shellcode)(void *);

shellcode   getSymbol(Elf64_Ehdr *header);

#endif
