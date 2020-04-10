#include "famine.h"

int  writeToFile(const char *dirname, const char *filename, struct bfile header) {
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
