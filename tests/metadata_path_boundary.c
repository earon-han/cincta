#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Relative operations can reach objects whose absolute procfs FD target is
 * at or beyond PATH_MAX. Print independent fstat observations for the driver;
 * the driver also walks directory FDs to verify the actual inode externally. */
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    char *end;
    errno = 0;
    unsigned long target = strtoul(argv[2], &end, 10);
    size_t current = strlen(argv[1]);
    if (errno || !*argv[2] || *end || target <= current + 1 || target > 8192) return 2;
    if (chdir(argv[1]) < 0) return 3;
    char component[201];
    memset(component, 'd', sizeof(component) - 1); component[sizeof(component) - 1] = 0;
    unsigned levels = 0;
    while (target - current - 1 > 200) {
        if (mkdir(component, 0700) < 0 || chdir(component) < 0) return 4;
        current += strlen(component) + 1; ++levels;
    }
    size_t leaf_size = target - current - 1;
    char leaf[201]; memset(leaf, 'f', leaf_size); leaf[leaf_size] = 0;
    int fd = open(leaf, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) return 5;
    errno = 0;
    int result = (int)syscall(SYS_fchmod, fd, 0644);
    int saved = errno;
    struct stat st;
    if (fstat(fd, &st) < 0) return 6;
    printf("{\"path_bytes\":%lu,\"directory_levels\":%u,\"leaf_bytes\":%zu,"
           "\"fchmod_syscall\":%ld,\"fchmod_rc\":%d,\"fchmod_errno\":%d,\"mode\":%u}\n",
           target, levels, leaf_size, (long)SYS_fchmod, result, saved, (unsigned)(st.st_mode & 0777));
    if (close(fd) < 0) return 7;
    return 0;
}
