#define _GNU_SOURCE
/* Minimal PID 1 for QEMU full-system validation. Never used by the product. */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static void directory(const char *name, mode_t mode)
{
    if (mkdir(name, mode) == 0) {
        if (chmod(name, mode) < 0) perror(name);
    } else if (errno != EEXIST) perror(name);
}

static void write_file(const char *name, const char *text)
{
    int fd = open(name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) { perror(name); return; }
    ssize_t n = write(fd, text, strlen(text));
    if (n != (ssize_t)strlen(text)) perror("write init fixture");
    close(fd);
}

static void delegate_cgroup(void)
{
    directory("/sys/fs/cgroup", 0755);
    if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
        perror("mount cgroup2"); return;
    }
    write_file("/sys/fs/cgroup/cgroup.subtree_control", "+cpu +memory +pids");
    directory("/sys/fs/cgroup/cincta-x86", 0755);
    write_file("/sys/fs/cgroup/cincta-x86/cgroup.subtree_control", "+cpu +memory +pids");
    const char *owned[] = {"/sys/fs/cgroup/cincta-x86", "/sys/fs/cgroup/cincta-x86/cgroup.procs",
        "/sys/fs/cgroup/cincta-x86/cgroup.subtree_control"};
    for (size_t i = 0; i < sizeof(owned)/sizeof(owned[0]); ++i)
        if (chown(owned[i], 501, 1000) < 0) perror("delegate cgroup owner");
    directory("/sys/fs/cgroup/cincta-x86/manager", 0755);
}

int main(void)
{
    directory("/proc", 0755); directory("/sys", 0755);
    directory("/dev", 0755); directory("/tmp", 01777); directory("/run", 0755);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) perror("mount proc");
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) perror("mount sysfs");
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") < 0) perror("mount devtmpfs");
    directory("/sys/kernel/security", 0755);
    if (mount("securityfs", "/sys/kernel/security", "securityfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0)
        perror("mount securityfs");
    directory("/etc", 0755);
    write_file("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n");
    write_file("/etc/nsswitch.conf", "hosts: files dns\n");
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq request = {0}; strcpy(request.ifr_name, "lo");
        if (ioctl(sock, SIOCGIFFLAGS, &request) == 0) {
            request.ifr_flags |= IFF_UP | IFF_RUNNING;
            if (ioctl(sock, SIOCSIFFLAGS, &request) < 0) perror("loopback up");
        }
        close(sock);
    }
    directory("/fixtures", 0755); directory("/fixtures/write", 0700);
    if (chown("/fixtures/write", 501, 1000) < 0) perror("chown fixtures");
    write_file("/fixtures/secret", "host-readable-but-not-authorized\n");
    write_file("/fixtures/readable", "permitted\n");
    directory("/fixtures/workspace-source", 0755);
    if (chown("/fixtures/workspace-source", 501, 1000) < 0) perror("chown workspace source");
    write_file("/fixtures/workspace-source/original", "source-must-stay-unchanged\n");
    delegate_cgroup();
    struct utsname u;
    if (uname(&u) == 0) printf("CINCTA_X86_ENV {\"kernel\":\"%s\",\"architecture\":\"%s\",\"virtualization\":\"qemu-system-x86_64-tcg\"}\n", u.release, u.machine);
    fflush(stdout);
    pid_t test = fork();
    if (test == 0) {
        if (access("/sys/fs/cgroup/cincta-x86/manager/cgroup.procs", F_OK) == 0)
            write_file("/sys/fs/cgroup/cincta-x86/manager/cgroup.procs", "0");
        if (setgroups(0, NULL) < 0 || setgid(1000) < 0 || setuid(501) < 0) { perror("drop test identity"); _exit(125); }
        char *args[] = {"/x86-smoke", NULL};
        char *environment[] = {"PATH=/bin:/sbin", "LANG=C", NULL};
        execve(args[0], args, environment); perror("exec smoke"); _exit(125);
    }
    int test_status = 0;
    if (test < 0) perror("fork smoke");
    else {
        for (;;) {
            int status;
            pid_t got = waitpid(-1, &status, 0);
            if (got == test) { test_status = status; break; }
            if (got < 0 && errno != EINTR) break;
        }
    }
    printf("CINCTA_X86_INIT_EXIT %d\n", WIFEXITED(test_status) ? WEXITSTATUS(test_status) : 125);
    fflush(NULL); sync();
    reboot(RB_POWER_OFF);
    for (;;) pause();
}
