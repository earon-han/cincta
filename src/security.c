#define _GNU_SOURCE
#include "cincta.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/version.h>
#include <signal.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define CINCTA_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CINCTA_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "cincta supports only native Linux x86_64 and aarch64"
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "cincta currently supports little-endian native ABIs only"
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
#error "cincta requires Linux UAPI headers >= 6.2 (runtime kernel is probed separately)"
#endif
#if !defined(__NR_clone3) || !defined(__NR_io_uring_setup) || \
    !defined(__NR_io_uring_enter) || !defined(__NR_io_uring_register) || \
    !defined(__NR_pidfd_getfd) || !defined(__NR_pidfd_send_signal) || \
    !defined(__NR_process_madvise) || !defined(__NR_process_mrelease) || \
    !defined(__NR_mount_setattr) || !defined(__NR_open_tree) || \
    !defined(__NR_move_mount) || !defined(__NR_fsopen) || \
    !defined(__NR_fsconfig) || !defined(__NR_fsmount) || !defined(__NR_fspick)
#error "incomplete Linux UAPI syscall headers: refusing to build a weaker filter"
#endif

/* These immutable UAPI numbers and layouts are shared by the two supported
 * architectures. Defining the subset here avoids requiring 6.12 build headers.
 * Source: Linux v6.12 include/uapi/linux/landlock.h (syscall ABI, not copied
 * implementation code). Never silently omit a known access right. */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
struct ll_ruleset { uint64_t fs; uint64_t net; uint64_t scoped; };
struct ll_path { uint64_t allowed; int32_t fd; } __attribute__((packed));
#define LL_VERSION 1U
#define LL_PATH_BENEATH 1
#define LL_EXECUTE (UINT64_C(1) << 0)
#define LL_WRITE_FILE (UINT64_C(1) << 1)
#define LL_READ_FILE (UINT64_C(1) << 2)
#define LL_READ_DIR (UINT64_C(1) << 3)
#define LL_REMOVE_DIR (UINT64_C(1) << 4)
#define LL_REMOVE_FILE (UINT64_C(1) << 5)
#define LL_MAKE_DIR (UINT64_C(1) << 7)
#define LL_MAKE_REG (UINT64_C(1) << 8)
#define LL_MAKE_SOCK (UINT64_C(1) << 9)
#define LL_MAKE_FIFO (UINT64_C(1) << 10)
#define LL_MAKE_SYM (UINT64_C(1) << 12)
#define LL_REFER (UINT64_C(1) << 13)
#define LL_TRUNCATE (UINT64_C(1) << 14)
#define LL_FS_V3 ((UINT64_C(1) << 15) - 1)
#define LL_IOCTL_DEV (UINT64_C(1) << 15)
#define LL_SCOPE_UNIX (UINT64_C(1) << 0)
#define LL_SCOPE_SIGNAL (UINT64_C(1) << 1)

static int fail(char *buf, size_t size, const char *fmt, ...)
{
    int saved = errno;
    va_list args;
    va_start(args, fmt);
    if (size != 0) vsnprintf(buf, size, fmt, args);
    va_end(args);
    errno = saved;
    return -1;
}

static int landlock_version(void)
{
    return (int)syscall(__NR_landlock_create_ruleset, NULL, 0, LL_VERSION);
}

static int install_allow_filter(void)
{
    struct sock_filter insn[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
    struct sock_fprog prog = { .len = 1, .filter = insn };
    return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

int security_probe(struct capabilities *caps)
{
    int pipefd[2];
    memset(caps, 0, sizeof(*caps));
    caps->landlock_abi = landlock_version();
    if (caps->landlock_abi < 0) {
        caps->landlock_errno = errno;
        caps->landlock_abi = 0;
    }
    if (pipe2(pipefd, O_CLOEXEC) < 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        int saved = errno;
        close(pipefd[0]); close(pipefd[1]); errno = saved;
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            caps->seccomp_errno = errno;
            caps->landlock_errno = errno;
        } else {
            if (caps->landlock_abi > 0) {
                struct ll_ruleset attr = { .fs = LL_READ_FILE };
                int fd = (int)syscall(__NR_landlock_create_ruleset, &attr, 8, 0);
                if (fd < 0) caps->landlock_errno = errno;
                else {
                    if (syscall(__NR_landlock_restrict_self, fd, 0) < 0)
                        caps->landlock_errno = errno;
                    close(fd);
                }
            }
            if (install_allow_filter() == 0) caps->seccomp = true;
            else caps->seccomp_errno = errno;
        }
        if (caps->landlock_errno != 0) caps->landlock_abi = 0;
        ssize_t n;
        do { n = write(pipefd[1], caps, sizeof(*caps)); } while (n < 0 && errno == EINTR);
        _exit(n == (ssize_t)sizeof(*caps) ? 0 : 1);
    }
    close(pipefd[1]);
    ssize_t n;
    do { n = read(pipefd[0], caps, sizeof(*caps)); } while (n < 0 && errno == EINTR);
    close(pipefd[0]);
    int status;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof(*caps) || waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

/* All policy FDs are pinned before any Landlock rule is installed. Parent path
 * symlinks are resolved by open; a final symlink/special file is a policy error.
 * Authorization follows the resolved inode, never a later pathname lookup. */
static int install_landlock(const struct config *cfg, int abi, char *error, size_t size)
{
    struct ll_ruleset attr = { .fs = LL_FS_V3 };
    int paths[CINCTA_MAX_RULES];
    uint64_t masks[CINCTA_MAX_RULES];
    size_t opened = 0;
    int ruleset = -1;
    int result = -1;
    if (cfg->rule_count > CINCTA_MAX_RULES) {
        errno = E2BIG;
        return fail(error, size, "too many path rules");
    }
    if (abi >= 5) attr.fs |= LL_IOCTL_DEV;
    if (abi >= 6) attr.scoped = LL_SCOPE_UNIX | LL_SCOPE_SIGNAL;
    for (size_t i = 0; i < cfg->rule_count; ++i) {
        const struct path_rule *rule = &cfg->rules[i];
        struct stat st;
        if (rule->path == NULL || rule->path[0] != '/') {
            errno = EINVAL;
            fail(error, size, "path rules must use absolute paths");
            goto out;
        }
        int fd = open(rule->path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            fail(error, size, "open rule '%s': %s", rule->path, strerror(errno));
            goto out;
        }
        paths[opened++] = fd;
        if (fstat(fd, &st) < 0) {
            fail(error, size, "stat rule '%s': %s", rule->path, strerror(errno));
            goto out;
        }
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
            errno = EINVAL;
            fail(error, size, "rule '%s' must be a regular file or directory (not a symlink/device)", rule->path);
            goto out;
        }
        uint64_t allowed = LL_READ_FILE;
        if (S_ISDIR(st.st_mode)) allowed |= LL_READ_DIR;
        if (rule->mode == PATH_RX) allowed |= LL_EXECUTE;
        else if (rule->mode == PATH_RW) {
            allowed |= LL_WRITE_FILE | LL_TRUNCATE;
            if (S_ISDIR(st.st_mode))
                allowed |= LL_REMOVE_DIR | LL_REMOVE_FILE | LL_MAKE_DIR | LL_MAKE_REG |
                           LL_MAKE_SOCK | LL_MAKE_FIFO | LL_MAKE_SYM | LL_REFER;
        } else if (rule->mode != PATH_RO) {
            errno = EINVAL;
            fail(error, size, "invalid mode for rule '%s'", rule->path);
            goto out;
        }
        masks[i] = allowed;
    }
    /* ABI 1-3 take 8 bytes, ABI 4-5 take 16, ABI 6+ takes 24. */
    size_t attr_size = abi >= 6 ? 24 : (abi >= 4 ? 16 : 8);
    ruleset = (int)syscall(__NR_landlock_create_ruleset, &attr, attr_size, 0);
    if (ruleset < 0) {
        fail(error, size, "landlock_create_ruleset: %s", strerror(errno));
        goto out;
    }
    for (size_t i = 0; i < opened; ++i) {
        struct ll_path path = { .allowed = masks[i], .fd = paths[i] };
        if (syscall(__NR_landlock_add_rule, ruleset, LL_PATH_BENEATH, &path, 0) < 0) {
            fail(error, size, "landlock_add_rule '%s': %s", cfg->rules[i].path, strerror(errno));
            goto out;
        }
    }
    if (syscall(__NR_landlock_restrict_self, ruleset, 0) < 0) {
        fail(error, size, "landlock_restrict_self: %s", strerror(errno));
        goto out;
    }
    result = 0;
out:;
    int saved = errno;
    if (ruleset >= 0) close(ruleset);
    for (size_t i = 0; i < opened; ++i) close(paths[i]);
    errno = saved;
    return result;
}

struct filter_builder { struct sock_filter code[512]; unsigned count; };
static void emit(struct filter_builder *b, unsigned short op, unsigned char jt,
                 unsigned char jf, uint32_t k)
{
    /* Fixed program size is below 512; checked again before installation. */
    if (b->count < 512) b->code[b->count] = (struct sock_filter){ op, jt, jf, k };
    ++b->count;
}
static void deny(struct filter_builder *b, unsigned nr, unsigned err)
{
    emit(b, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, nr);
    emit(b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | err);
}

static void deny_arg1(struct filter_builder *b, unsigned nr, unsigned arg)
{
    emit(b, BPF_JMP | BPF_JEQ | BPF_K, 0, 3, nr);
    emit(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[1]));
    emit(b, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, arg);
    emit(b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
    emit(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
}

static int install_seccomp(const struct config *cfg, int abi)
{
    struct filter_builder b = { .count = 0 };
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, arch));
    emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, CINCTA_AUDIT_ARCH);
    emit(&b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    /* x32 uses the same audit architecture as x86_64 but a different ABI. */
    emit(&b, BPF_JMP | BPF_JSET | BPF_K, 0, 1, 0x40000000U);
    emit(&b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);
#endif
#ifdef __NR_clone3
    deny(&b, __NR_clone3, ENOSYS); /* libc may fall back to inspectable clone. */
#endif
#ifdef __NR_clone
    emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 0, 3, __NR_clone);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[0]));
    emit(&b, BPF_JMP | BPF_JSET | BPF_K, 0, 1,
         CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
         CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_PARENT);
    emit(&b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
#endif
#ifdef __NR_prlimit64
    /* Resource accounting is per process. Do not let a payload lower limits
     * on a same-UID unsandboxed supervisor or unrelated host process. */
    emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 0, 3, __NR_prlimit64);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[0]));
    emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0);
    emit(&b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
#endif
#ifdef __NR_fcntl
    /* Standard streams remain inherited capabilities. Do not let a pipe or
     * terminal's async notification ownership target the trusted caller. */
    deny_arg1(&b, __NR_fcntl, F_SETOWN);
#ifdef F_SETOWN_EX
    deny_arg1(&b, __NR_fcntl, F_SETOWN_EX);
#endif
#ifdef F_SETSIG
    deny_arg1(&b, __NR_fcntl, F_SETSIG);
#endif
    emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 0, 6, __NR_fcntl);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[1]));
    emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 0, 3, F_SETFL);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[2]));
    emit(&b, BPF_JMP | BPF_JSET | BPF_K, 0, 1, O_ASYNC);
    emit(&b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
    emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
#endif
#define DENY(name) deny(&b, __NR_##name, EPERM)
#ifdef __NR_ioctl
    /* Includes TIOCSTI and TIOCLINUX: no interactive terminal control in v0.1. */
    DENY(ioctl);
#endif
#ifdef __NR_setpriority
    DENY(setpriority);
#endif
#ifdef __NR_sched_setaffinity
    DENY(sched_setaffinity);
#endif
#ifdef __NR_sched_setparam
    DENY(sched_setparam);
#endif
#ifdef __NR_sched_setscheduler
    DENY(sched_setscheduler);
#endif
#ifdef __NR_sched_setattr
    DENY(sched_setattr);
#endif
#ifdef __NR_process_madvise
    DENY(process_madvise);
#endif
#ifdef __NR_process_mrelease
    DENY(process_mrelease);
#endif
#ifdef __NR_migrate_pages
    DENY(migrate_pages);
#endif
#ifdef __NR_move_pages
    DENY(move_pages);
#endif
#ifdef __NR_inotify_init
    DENY(inotify_init);
#endif
#ifdef __NR_inotify_init1
    DENY(inotify_init1);
#endif
#ifdef __NR_inotify_add_watch
    DENY(inotify_add_watch);
#endif
#ifdef __NR_inotify_rm_watch
    DENY(inotify_rm_watch);
#endif
#ifdef __NR_fanotify_init
    DENY(fanotify_init);
#endif
#ifdef __NR_fanotify_mark
    DENY(fanotify_mark);
#endif
#ifdef __NR_setsid
    DENY(setsid);
#endif
#ifdef __NR_setpgid
    DENY(setpgid);
#endif
#ifdef __NR_unshare
    DENY(unshare);
#endif
#ifdef __NR_setns
    DENY(setns);
#endif
#ifdef __NR_ptrace
    DENY(ptrace);
#endif
#ifdef __NR_process_vm_readv
    DENY(process_vm_readv);
#endif
#ifdef __NR_process_vm_writev
    DENY(process_vm_writev);
#endif
#ifdef __NR_pidfd_getfd
    DENY(pidfd_getfd);
#endif
#ifdef __NR_bpf
    DENY(bpf);
#endif
#ifdef __NR_perf_event_open
    DENY(perf_event_open);
#endif
#ifdef __NR_userfaultfd
    DENY(userfaultfd);
#endif
#ifdef __NR_io_uring_setup
    DENY(io_uring_setup);
#endif
#ifdef __NR_io_uring_enter
    DENY(io_uring_enter);
#endif
#ifdef __NR_io_uring_register
    DENY(io_uring_register);
#endif
#ifdef __NR_mount
    DENY(mount);
#endif
#ifdef __NR_umount2
    DENY(umount2);
#endif
#ifdef __NR_pivot_root
    DENY(pivot_root);
#endif
#ifdef __NR_chroot
    DENY(chroot);
#endif
#ifdef __NR_fsopen
    DENY(fsopen);
#endif
#ifdef __NR_fsconfig
    DENY(fsconfig);
#endif
#ifdef __NR_fsmount
    DENY(fsmount);
#endif
#ifdef __NR_fspick
    DENY(fspick);
#endif
#ifdef __NR_open_tree
    DENY(open_tree);
#endif
#ifdef __NR_move_mount
    DENY(move_mount);
#endif
#ifdef __NR_mount_setattr
    DENY(mount_setattr);
#endif
#ifdef __NR_keyctl
    DENY(keyctl);
#endif
#ifdef __NR_add_key
    DENY(add_key);
#endif
#ifdef __NR_request_key
    DENY(request_key);
#endif
#ifdef __NR_open_by_handle_at
    DENY(open_by_handle_at);
#endif
#ifdef __NR_name_to_handle_at
    DENY(name_to_handle_at);
#endif
#ifdef __NR_reboot
    DENY(reboot);
#endif
#ifdef __NR_kexec_load
    DENY(kexec_load);
#endif
#ifdef __NR_kexec_file_load
    DENY(kexec_file_load);
#endif
#ifdef __NR_init_module
    DENY(init_module);
#endif
#ifdef __NR_finit_module
    DENY(finit_module);
#endif
#ifdef __NR_delete_module
    DENY(delete_module);
#endif
#ifdef __NR_swapon
    DENY(swapon);
#endif
#ifdef __NR_swapoff
    DENY(swapoff);
#endif
#ifdef __NR_acct
    DENY(acct);
#endif
#ifdef __NR_quotactl
    DENY(quotactl);
#endif
#ifdef __NR_iopl
    DENY(iopl);
#endif
#ifdef __NR_ioperm
    DENY(ioperm);
#endif
#ifdef __NR_personality
    DENY(personality);
#endif
#ifdef __NR_modify_ldt
    DENY(modify_ldt);
#endif
#ifdef __NR_capset
    DENY(capset);
#endif
#ifdef __NR_setuid
    DENY(setuid);
#endif
#ifdef __NR_setgid
    DENY(setgid);
#endif
#ifdef __NR_setreuid
    DENY(setreuid);
#endif
#ifdef __NR_setregid
    DENY(setregid);
#endif
#ifdef __NR_setresuid
    DENY(setresuid);
#endif
#ifdef __NR_setresgid
    DENY(setresgid);
#endif
#ifdef __NR_setfsuid
    DENY(setfsuid);
#endif
#ifdef __NR_setfsgid
    DENY(setfsgid);
#endif
#ifdef __NR_setgroups
    DENY(setgroups);
#endif
    /* Landlock's file access rights do not mediate metadata changes. Deny all
     * path, FD and *at variants rather than relying on filesystem grants. */
#ifdef __NR_chmod
    DENY(chmod);
#endif
#ifdef __NR_fchmod
    DENY(fchmod);
#endif
#ifdef __NR_fchmodat
    DENY(fchmodat);
#endif
#ifdef __NR_fchmodat2
    DENY(fchmodat2);
#else
    deny(&b, 452, EPERM); /* fchmodat2: stable number on both native ABIs */
#endif
#ifdef __NR_chown
    DENY(chown);
#endif
#ifdef __NR_fchown
    DENY(fchown);
#endif
#ifdef __NR_lchown
    DENY(lchown);
#endif
#ifdef __NR_fchownat
    DENY(fchownat);
#endif
#ifdef __NR_utime
    DENY(utime);
#endif
#ifdef __NR_utimes
    DENY(utimes);
#endif
#ifdef __NR_futimesat
    DENY(futimesat);
#endif
#ifdef __NR_utimensat
    DENY(utimensat);
#endif
#ifdef __NR_setxattr
    DENY(setxattr);
#endif
#ifdef __NR_lsetxattr
    DENY(lsetxattr);
#endif
#ifdef __NR_fsetxattr
    DENY(fsetxattr);
#endif
#ifdef __NR_removexattr
    DENY(removexattr);
#endif
#ifdef __NR_lremovexattr
    DENY(lremovexattr);
#endif
#ifdef __NR_fremovexattr
    DENY(fremovexattr);
#endif
    /* New *xattrat metadata-writing calls (Linux 6.13), including when built
     * using older headers. get/list variants carry no mutation authority. */
    deny(&b, 463, EPERM); /* setxattrat */
    deny(&b, 466, EPERM); /* removexattrat */
#ifdef __NR_shmget
    DENY(shmget);
#endif
#ifdef __NR_shmat
    DENY(shmat);
#endif
#ifdef __NR_shmctl
    DENY(shmctl);
#endif
#ifdef __NR_semget
    DENY(semget);
#endif
#ifdef __NR_semop
    DENY(semop);
#endif
#ifdef __NR_semtimedop
    DENY(semtimedop);
#endif
#ifdef __NR_semctl
    DENY(semctl);
#endif
#ifdef __NR_msgget
    DENY(msgget);
#endif
#ifdef __NR_msgsnd
    DENY(msgsnd);
#endif
#ifdef __NR_msgrcv
    DENY(msgrcv);
#endif
#ifdef __NR_msgctl
    DENY(msgctl);
#endif
#ifdef __NR_mq_open
    DENY(mq_open);
#endif
#ifdef __NR_mq_unlink
    DENY(mq_unlink);
#endif
    /* Without ABI 6 scopes there is no safe way for static BPF to determine
     * whether an arbitrary numeric PID is a sibling, descendant or supervisor.
     * Conservatively deny signal-send entry points, including queued variants. */
    if (abi < 6) {
#ifdef __NR_kill
        DENY(kill);
#endif
#ifdef __NR_tkill
        DENY(tkill);
#endif
#ifdef __NR_tgkill
        DENY(tgkill);
#endif
#ifdef __NR_pidfd_send_signal
        DENY(pidfd_send_signal);
#endif
#ifdef __NR_rt_sigqueueinfo
        DENY(rt_sigqueueinfo);
#endif
#ifdef __NR_rt_tgsigqueueinfo
        DENY(rt_tgsigqueueinfo);
#endif
    }
    /* Unix sockets may delegate FDs with SCM_RIGHTS, and netlink/raw families
     * expose unrelated host authority. The explicit host mode is IP only. */
#ifdef __NR_socketpair
    DENY(socketpair);
#endif
    if (cfg->network_host) {
#ifdef __NR_socket
        emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 0, 5, __NR_socket);
        emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[0]));
        emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 2, 0, AF_INET);
        emit(&b, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AF_INET6);
        emit(&b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
        emit(&b, BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
#endif
    } else {
#ifdef __NR_socket
        DENY(socket);
#endif
#ifdef __NR_connect
        DENY(connect);
#endif
#ifdef __NR_bind
        DENY(bind);
#endif
#ifdef __NR_listen
        DENY(listen);
#endif
#ifdef __NR_accept
        DENY(accept);
#endif
#ifdef __NR_accept4
        DENY(accept4);
#endif
#ifdef __NR_sendto
        DENY(sendto);
#endif
#ifdef __NR_sendmsg
        DENY(sendmsg);
#endif
#ifdef __NR_sendmmsg
        DENY(sendmmsg);
#endif
#ifdef __NR_recvmsg
        DENY(recvmsg);
#endif
#ifdef __NR_recvmmsg
        DENY(recvmmsg);
#endif
#ifdef __NR_recvfrom
        DENY(recvfrom);
#endif
    }
#undef DENY
    emit(&b, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
    if (b.count > 512) { errno = E2BIG; return -1; }
    struct sock_fprog prog = { .len = (unsigned short)b.count, .filter = b.code };
    return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

static int clear_capabilities(void)
{
    /* UID 0 has special capability regain semantics at exec. Remove the full
     * bounding set before clearing CAP_SETPCAP; fail closed if this is blocked.
     * Unprivileged non-root callers need no bounding-set modifications. */
    if (getuid() == 0 || geteuid() == 0) {
        for (unsigned cap = 0; cap < 64; ++cap) {
            int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
            if (present < 0) {
                if (errno == EINVAL) break;
                return -1;
            }
            if (present && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) return -1;
        }
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) return -1;
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    return (int)syscall(__NR_capset, &header, data);
}

int security_apply(const struct config *cfg, struct capabilities *caps,
                   char *error, size_t error_size)
{
    int abi = landlock_version();
    if (abi < 0) {
        caps->landlock_errno = errno;
        return fail(error, error_size, "Landlock unavailable: %s", strerror(errno));
    }
    caps->landlock_abi = abi;
    if (abi < 3 || (!cfg->compat && abi < 6)) {
        errno = ENOTSUP;
        return fail(error, error_size, "Landlock ABI %d; require ABI %d%s", abi,
                    cfg->compat ? 3 : 6, cfg->compat ? "" : " (explicit --compat allows ABI 3+ without scopes)");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return fail(error, error_size, "set no_new_privs: %s", strerror(errno));
    if (clear_capabilities() < 0)
        return fail(error, error_size, "clear capabilities/bounding set: %s", strerror(errno));
    if (install_landlock(cfg, abi, error, error_size) < 0) {
        caps->landlock_errno = errno;
        return -1;
    }
    if (install_seccomp(cfg, abi) < 0) {
        caps->seccomp = false;
        caps->seccomp_errno = errno;
        return fail(error, error_size, "install seccomp filter: %s", strerror(errno));
    }
    caps->seccomp = true;
    return 0;
}
