#define _GNU_SOURCE
/* Small direct-syscall workload. Exit 0 means the operation succeeded; errno is
 * printed as JSON and returned on failure. No shell command aliases or mocks. */
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static int outcome(const char *operation, long value)
{
    int error = value < 0 ? errno : 0;
    printf("{\"operation\":\"%s\",\"allowed\":%s,\"errno\":%d}\n",
           operation, error == 0 ? "true" : "false", error);
    return error > 125 ? 1 : error;
}

static int publish_pid(const char *path, pid_t pid)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    char text[64];
    int count = snprintf(text, sizeof(text), "%ld\n", (long)pid);
    ssize_t written = write(fd, text, (size_t)count);
    int saved = errno;
    close(fd);
    errno = saved;
    return written == count ? 0 : -1;
}

static int deny_then_exec(unsigned syscall_number, char **command)
{
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) < 0) {
        perror("fault injection seccomp installation");
        return 125;
    }
    execv(command[0], command);
    perror("fault injection exec");
    return 125;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 125;
    const char *op = argv[1];
    const char *arg = argc > 2 ? argv[2] : "";
    if (argc > 2 && !strcmp(op, "deny-landlock-exec"))
        return deny_then_exec(444, &argv[2]);
    if (argc > 2 && !strcmp(op, "deny-add-rule-exec"))
        return deny_then_exec(445, &argv[2]);
    if (argc > 2 && !strcmp(op, "deny-seccomp-exec"))
        return deny_then_exec(SYS_seccomp, &argv[2]);
    long value = -1;
    if (!strcmp(op, "read")) {
        int fd = open(arg, O_RDONLY);
        if (fd >= 0) {
            char byte;
            value = read(fd, &byte, 1);
            close(fd);
        }
    } else if (!strcmp(op, "write")) {
        int fd = open(arg, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            value = write(fd, "x", 1);
            close(fd);
        }
    } else if (!strcmp(op, "truncate")) {
        value = truncate(arg, 0);
    } else if (!strcmp(op, "chmod")) {
        value = chmod(arg, 0600);
    } else if (!strcmp(op, "chown")) {
        value = chown(arg, getuid(), getgid());
    } else if (!strcmp(op, "utime")) {
        value = utimensat(AT_FDCWD, arg, NULL, 0);
    } else if (!strcmp(op, "xattr")) {
        value = setxattr(arg, "user.cincta", "x", 1, 0);
    } else if (!strcmp(op, "fd-read")) {
        char byte;
        value = read(atoi(arg), &byte, 1);
    } else if (!strcmp(op, "fd-write")) {
        value = write(atoi(arg), "x", 1);
    } else if (!strcmp(op, "link") && argc > 3) {
        value = link(arg, argv[3]);
    } else if (!strcmp(op, "rename") && argc > 3) {
        value = rename(arg, argv[3]);
    } else if (!strcmp(op, "socket")) {
        int family = !strcmp(arg, "inet6") ? AF_INET6 :
                     !strcmp(arg, "unix") ? AF_UNIX :
                     !strcmp(arg, "netlink") ? AF_NETLINK : AF_INET;
        value = socket(family, argc > 3 && !strcmp(argv[3], "udp") ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (value >= 0)
            close((int)value);
    } else if (!strcmp(op, "socketpair")) {
        int pair[2];
        value = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        if (value >= 0) {
            close(pair[0]);
            close(pair[1]);
        }
    } else if (!strcmp(op, "ptrace")) {
        value = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    } else if (!strcmp(op, "bpf")) {
        union bpf_attr attr = {0};
        value = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    } else if (!strcmp(op, "unshare")) {
        value = syscall(SYS_unshare, CLONE_NEWUSER);
    } else if (!strcmp(op, "setsid")) {
        value = setsid();
    } else if (!strcmp(op, "setpgid")) {
        value = setpgid(0, 0);
    } else if (!strcmp(op, "clone-ns")) {
        value = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, NULL, NULL, NULL, 0);
        if (value == 0)
            _exit(0);
        if (value > 0)
            waitpid((pid_t)value, NULL, 0);
    } else if (!strcmp(op, "clone-parent")) {
        value = syscall(SYS_clone, CLONE_PARENT | SIGCHLD, NULL, NULL, NULL, 0);
        if (value == 0)
            _exit(0);
    } else if (!strcmp(op, "clone3")) {
#ifdef SYS_clone3
        struct clone_args args = {0};
        args.exit_signal = SIGCHLD;
        value = syscall(SYS_clone3, &args, sizeof(args));
        if (value == 0)
            _exit(0);
        if (value > 0)
            waitpid((pid_t)value, NULL, 0);
#else
        errno = ENOSYS;
#endif
    } else if (!strcmp(op, "fork")) {
        value = fork();
        if (value == 0)
            _exit(0);
        if (value > 0)
            waitpid((pid_t)value, NULL, 0);
    } else if (!strcmp(op, "io-uring")) {
#ifdef SYS_io_uring_setup
        unsigned char params[256] = {0};
        value = syscall(SYS_io_uring_setup, 1, params);
#else
        errno = ENOSYS;
#endif
    } else if (!strcmp(op, "kill-external")) {
        value = kill((pid_t)atoi(arg), SIGCONT);
    } else if (!strcmp(op, "ioctl")) {
        int available = 0;
        value = ioctl(STDOUT_FILENO, FIONREAD, &available);
    } else if (!strcmp(op, "fcntl-setown")) {
        value = fcntl(STDOUT_FILENO, F_SETOWN, getpid());
    } else if (!strcmp(op, "fcntl-async")) {
        value = fcntl(STDOUT_FILENO, F_SETFL, O_ASYNC);
    } else if (!strcmp(op, "get-nnp")) {
        value = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 0 : -1;
    } else if (!strcmp(op, "limit-fd")) {
        struct rlimit limit;
        value = getrlimit(RLIMIT_NOFILE, &limit);
        if (value == 0 && limit.rlim_cur != (rlim_t)strtoul(arg, NULL, 10)) {
            errno = ERANGE;
            value = -1;
        }
    } else if (!strcmp(op, "allocate")) {
        size_t size = (size_t)strtoul(arg, NULL, 10) * 1024 * 1024;
        void *allocation = malloc(size);
        if (allocation) {
            memset(allocation, 1, size);
            volatile unsigned char sink = ((unsigned char *)allocation)[size - 1];
            (void)sink;
            free(allocation);
            value = 0;
        }
    } else if (!strcmp(op, "spawn") || !strcmp(op, "tree") || !strcmp(op, "spawn-clone-zero")) {
        pid_t child = !strcmp(op, "spawn-clone-zero")
            ? (pid_t)syscall(SYS_clone, 0, NULL, NULL, NULL, 0) : fork();
        if (child == 0) {
            if (publish_pid(arg, getpid()) < 0)
                _exit(125);
            for (;;)
                pause();
        }
        if (child < 0)
            return outcome(op, -1);
        /* Wait for the marker so the supervisor cannot win the test's race. */
        struct stat st;
        for (int attempt = 0; attempt < 1000 && stat(arg, &st) < 0; attempt++)
            usleep(1000);
        if (!strcmp(op, "tree"))
            for (;;)
                pause();
        return 0;
    } else if (!strcmp(op, "signal")) {
        signal(atoi(arg), SIG_DFL);
        raise(atoi(arg));
        return 125;
    } else if (!strcmp(op, "cpu")) {
        volatile uint64_t counter = 0;
        for (;;)
            counter++;
    } else if (!strcmp(op, "x32")) {
#if defined(__x86_64__)
        value = syscall(0x40000000UL | SYS_getpid);
#else
        errno = ENOSYS;
#endif
    } else if (!strcmp(op, "i386-entry")) {
#if defined(__x86_64__)
        __asm__ volatile("movl $20, %%eax\n\tint $0x80" : "=a"(value) : : "memory");
#else
        errno = ENOSYS;
#endif
    } else {
        errno = EINVAL;
    }
    return outcome(op, value);
}
