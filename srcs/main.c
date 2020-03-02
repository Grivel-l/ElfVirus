#include "famine.h"

static int  mapFile(const char *dirname, const char *filename, struct bfile *file) {
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
  if ((file->header = mmap(NULL, file->size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    close(fd);
    return (-1);
  }
  return (0);
}

static int  isCompatible(unsigned char e_ident[EI_NIDENT], Elf64_Half e_machine) {
  return (e_ident[EI_MAG0] == ELFMAG0 &&
          e_ident[EI_MAG1] == ELFMAG1 &&
          e_ident[EI_MAG2] == ELFMAG2 &&
          e_ident[EI_MAG3] == ELFMAG3 &&
          e_machine == EM_X86_64);
}

static int  infectFile(const char *dirname, struct dirent *file) {
  struct bfile  header;

  if (mapFile(dirname, file->d_name, &header) == -1)
    return (0);
  if (!isCompatible(header.header->e_ident, header.header->e_machine))
    return (0);
  return (0);
}

static int  infectBins(const char *dirname) {
  DIR *dir;
  struct dirent *file;

  if ((dir = opendir(dirname)) == NULL)
    return (-1);
  while ((file = readdir(dir)) != NULL) {
    if (infectFile(dirname, file) == -1) {
      closedir(dir);
      return (-1);
    }
  }
  closedir(dir);
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
