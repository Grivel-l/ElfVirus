#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int   main(int argc, char **argv) {
  int         fd;
  off_t       size;
  struct stat stats;
  char        *content;

  if (argc != 2) {
    write(1, "Not right number of arguments\n", 30);
    return (1);
  }
  if ((fd = open(argv[1], O_RDONLY)) == -1)
    return (1);
  if (fstat(fd, &stats) == -1) {
    close(fd);
    return (1);
  }
  if ((content = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    close(fd);
    return (1);
  }
  close(fd);
  size = 0;
  while (size < stats.st_size) {
    content[size] ^= 0xa5;
    size += 1;
  }
  if ((fd = open("./obfuscated", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH)) == -1) {
    munmap(content, stats.st_size);
    return (1);
  }
  write(fd, content, stats.st_size);
  close(fd);
  munmap(content, stats.st_size);
  write(1, "Created obfuscated payload: ./obfuscated\n", 41);
  return (0);
}
