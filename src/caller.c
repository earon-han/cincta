#define _GNU_SOURCE
#include "cincta.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <unistd.h>

int caller_alive(int fd)
{
    if (fd < 0) return 1;
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int ready;
    do { ready = poll(&p, 1, 0); } while (ready < 0 && errno == EINTR);
    if (ready < 0) return -1;
    if (p.revents & POLLNVAL) { errno = EBADF; return -1; }
    return ready ? 0 : 1;
}

int caller_capture(int *fd)
{
    *fd = -1;
    pid_t parent = getppid();
    if (parent == 0 && getpid() == 1) return 0;
    if (parent <= 0) { errno = ESRCH; return -1; }
    int pinned = (int)syscall(SYS_pidfd_open, parent, 0);
    if (pinned < 0) return -1;
    if (pinned < 3) {
        int high = fcntl(pinned, F_DUPFD_CLOEXEC, 3);
        int saved = errno; close(pinned); errno = saved; pinned = high;
        if (pinned < 0) return -1;
    }
    if (getppid() != parent || caller_alive(pinned) != 1) {
        close(pinned); errno = ESRCH; return -1;
    }
    *fd = pinned;
    return 0;
}
