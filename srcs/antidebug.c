#include "famine.h"

int  preventDebug(void) {
  pid_t pid;

  if ((pid = fork()) == -1)
    return (-1);
  if (pid != 0) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1 ||
        waitpid(pid, 0, 0) == -1) {
      kill(pid, SIGTERM);
      return (-1);
    }
    exit(0);
  } else {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
      exit(1);
  }
  return (0);
}
