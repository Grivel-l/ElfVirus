#include "virus.h"
#define DEBUG
#define PAYLOAD_SIZE 0
#define PAYLOAD_CONTENT ""

int   main(void) {
  shellcode code;
  shellcode fun;

  #ifdef DEBUG
    system("gcc -fno-stack-protector -I ./includes/ -c srcs/infection.c -o infection.o");
    int           fd;
    struct stat   stats;
    if ((fd = open("./infection.o", O_RDONLY)) == 0)
      return (1);
    if (fstat(fd, &stats) == -1)
      return (1);
    if ((code = mmap(0, stats.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
      return (1);
    close(fd);
  #else
    if ((code = mmap(0, PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
      return (1);
    memcpy(code, PAYLOAD_CONTENT, PAYLOAD_SIZE);
  #endif
  if ((fun = getSymbol((Elf64_Ehdr *)(code))) == NULL)
    return (-1);
  dprintf(1, "Ret: %i\n", fun((void *)0x42));
  #ifdef DEBUG
    munmap(code, stats.st_size);
  #else
    munmap(code, PAYLOAD_SIZE);
  #endif
  return (0);
}
