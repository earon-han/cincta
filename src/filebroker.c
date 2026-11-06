#define _GNU_SOURCE
#include "filebroker.h"
#include "broker.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t workers[CINCTA_FILE_MAX_WORKERS];

struct open_request {
    char path[PATH_MAX];
    struct open_how how;
    int base;
    mode_t mask;
};

static int valid_id(int listener, uint64_t id)
{
    int rc;
    do { rc = ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id); }
    while (rc < 0 && errno == EINTR);
    return rc;
}

/* The real ancestor monitor opens mem before ID_VALID and passes the pinned
 * address space over the private broker channel. A sibling broker cannot use
 * PR_SET_PTRACER from the original payload to inspect its fork descendants. */
static int memory_open(int listener, const struct seccomp_notif *request)
{
    return broker_memory_open(listener, request, false);
}

static int memory_read(int memory, uint64_t address, void *out, size_t length)
{
    if (!address || address > INT64_MAX || length > INT64_MAX - address) {
        errno = EFAULT; return -1;
    }
    ssize_t got;
    do { got = pread(memory, out, length, (off_t)address); }
    while (got < 0 && errno == EINTR);
    if (got != (ssize_t)length) { errno = EFAULT; return -1; }
    return 0;
}

static int memory_string(int memory, uint64_t address, char *out, size_t size)
{
    /* Byte reads preserve a valid string ending immediately before an
     * unmapped page. /proc/TID/mem is opened just once per request. */
    for (size_t i = 0; i < size; ++i) {
        if (address > UINT64_MAX - i || memory_read(memory, address + i, out + i, 1) < 0) return -1;
        if (!out[i]) return 0;
    }
    errno = ENAMETOOLONG; return -1;
}

static int target_umask(int listener, const struct seccomp_notif *request, mode_t *mask)
{
    char name[80], line[256];
    snprintf(name, sizeof(name), "/proc/%u/status", request->pid);
    FILE *f = fopen(name, "re");
    if (!f) return -1;
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned value;
        if (sscanf(line, "Umask:\t%o", &value) == 1) {
            if (value <= 0777) { *mask = (mode_t)value; found = true; }
            break;
        }
    }
    int failed = ferror(f);
    fclose(f);
    if (failed || !found) { errno = EIO; return -1; }
    return valid_id(listener, request->id);
}

static int directory_open(int listener, const struct seccomp_notif *request, int dirfd)
{
    char name[96];
    if (dirfd == AT_FDCWD) snprintf(name, sizeof(name), "/proc/%u/cwd", request->pid);
    else snprintf(name, sizeof(name), "/proc/%u/fd/%d", request->pid, dirfd);
    int fd = open(name, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct statfs fs;
    if (valid_id(listener, request->id) < 0 || fstatfs(fd, &fs) < 0) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    if ((unsigned long)fs.f_type == PROC_SUPER_MAGIC) { close(fd); errno = EOPNOTSUPP; return -1; }
    return fd;
}

static int capture_request(int listener, const struct seccomp_notif *r, struct open_request *out)
{
    *out = (struct open_request){.base = -1};
    int dirfd = AT_FDCWD;
    uint64_t path_address;
    int memory = memory_open(listener, r);
    if (memory < 0) return -1;
    int nr = r->data.nr;
#ifdef SYS_open
    if (nr == SYS_open) {
        path_address = r->data.args[0];
        out->how.flags = (unsigned)(int)r->data.args[1];
        out->how.mode = r->data.args[2] & 07777;
    } else
#endif
#ifdef SYS_creat
    if (nr == SYS_creat) {
        path_address = r->data.args[0];
        out->how.flags = O_WRONLY | O_CREAT | O_TRUNC;
        out->how.mode = r->data.args[1] & 07777;
    } else
#endif
    if (nr == SYS_openat) {
        dirfd = (int)r->data.args[0]; path_address = r->data.args[1];
        out->how.flags = (unsigned)(int)r->data.args[2];
        out->how.mode = r->data.args[3] & 07777;
    } else if (nr == SYS_openat2) {
        dirfd = (int)r->data.args[0]; path_address = r->data.args[1];
        uint64_t length = r->data.args[3];
        if (length < sizeof(out->how)) { close(memory); errno = EINVAL; return -1; }
        if (length > 4096) { close(memory); errno = E2BIG; return -1; }
        if (memory_read(memory, r->data.args[2], &out->how, sizeof(out->how)) < 0) {
            int saved = errno; close(memory); errno = saved; return -1;
        }
        /* Kernel accepts zero-filled extensions, rejects unknown nonzero
         * fields. Never read unbounded user-provided structure lengths. */
        unsigned char extension[256];
        for (uint64_t offset = sizeof(out->how); offset < length;) {
            size_t amount = length - offset < sizeof(extension) ? (size_t)(length - offset) : sizeof(extension);
            if (r->data.args[2] > UINT64_MAX - offset ||
                memory_read(memory, r->data.args[2] + offset, extension, amount) < 0) {
                int saved = errno; close(memory); errno = saved; return -1;
            }
            for (size_t i = 0; i < amount; ++i) if (extension[i]) { close(memory); errno = E2BIG; return -1; }
            offset += amount;
        }
    } else { close(memory); errno = ENOSYS; return -1; }
    if (nr != SYS_openat2 && !(out->how.flags & O_CREAT) &&
        (out->how.flags & O_TMPFILE) != O_TMPFILE) out->how.mode = 0;
    if (memory_string(memory, path_address, out->path, sizeof(out->path)) < 0) {
        int saved = errno; close(memory); errno = saved; return -1;
    }
    close(memory);
    if (!out->path[0]) { errno = ENOENT; return -1; }
    if (target_umask(listener, r, &out->mask) < 0) return -1;
    /* IN_ROOT makes absolute paths relative to dirfd, unlike ordinary
     * open/openat. Retain that directory capability too. */
    if (out->path[0] != '/' || (out->how.resolve & RESOLVE_IN_ROOT)) {
        out->base = directory_open(listener, r, dirfd);
        if (out->base < 0) return -1;
    }
    if (valid_id(listener, r->id) < 0) {
        int saved = errno; if (out->base >= 0) close(out->base); out->base = -1; errno = saved; return -1;
    }
    return 0;
}

void filebroker_reap(void)
{
    for (size_t i = 0; i < CINCTA_FILE_MAX_WORKERS; ++i) {
        if (workers[i] <= 0) continue;
        int status;
        pid_t got = waitpid(workers[i], &status, WNOHANG);
        if (got == workers[i] || (got < 0 && errno == ECHILD)) workers[i] = 0;
    }
}

void filebroker_destroy(void)
{
    filebroker_reap();
    for (size_t i = 0; i < CINCTA_FILE_MAX_WORKERS; ++i)
        if (workers[i] > 0) kill(workers[i], SIGKILL);
    /* Caller must reap all remaining children before considering cleanup
     * complete. Do not block here on a task stuck in kernel I/O. */
}

static int close_other_fds(int listener, int audit, int base)
{
    int keep[] = {listener, audit, base};
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = i + 1; j < 3; ++j)
            if (keep[j] < keep[i]) { int swap = keep[i]; keep[i] = keep[j]; keep[j] = swap; }
    unsigned next = 3;
    for (size_t i = 0; i < 3; ++i) {
        if (keep[i] < 3 || (unsigned)keep[i] < next) continue;
        if ((unsigned)keep[i] > next && syscall(SYS_close_range, next, (unsigned)keep[i] - 1, 0) < 0) return -1;
        next = (unsigned)keep[i] + 1;
    }
    return (int)syscall(SYS_close_range, next, UINT_MAX, 0);
}

static void respond_error(int listener, const struct seccomp_notif *request, int error)
{
    struct seccomp_notif_resp response = {.id = request->id, .error = -error};
    int rc;
    do { rc = ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response); } while (rc < 0 && errno == EINTR);
}

static _Noreturn void worker_exit(const struct config *cfg, int code)
{
    /* Reserved by the parent before fork: it covers setup, actual open
     * (including create/truncate), result logging and response delivery.
     * A killed worker intentionally leaves this nonzero, so cleanup cannot
     * claim complete auditing after an unrecorded filesystem side effect. */
    if (cfg->state) --cfg->state->delivery_pending;
    _exit(code);
}

static int validate_how(const struct open_how *how)
{
    /* openat2 performs strict flag validation. Because the final operation may
     * use a private pinned FD path, validate bits before removing pathname-only
     * flags. The native x86_64/aarch64 UAPI share the kernel LARGEFILE bit. */
    uint64_t known = O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND |
        O_NONBLOCK | O_DSYNC | O_SYNC | O_ASYNC | O_DIRECT | O_DIRECTORY |
        O_NOFOLLOW | O_NOATIME | O_CLOEXEC | O_PATH | O_TMPFILE | UINT64_C(0100000);
    if (how->flags & ~known) { errno = EINVAL; return -1; }
    if ((how->flags & O_PATH) &&
        (how->flags & ~(uint64_t)(O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))) {
        errno = EINVAL; return -1;
    }
    bool temporary = (how->flags & O_TMPFILE) == O_TMPFILE;
    if ((how->mode & ~UINT64_C(07777)) ||
        (how->mode && !(how->flags & O_CREAT) && !temporary) ||
        ((how->flags & O_CREAT) && (how->flags & O_DIRECTORY)) ||
        (temporary && !(how->flags & O_WRONLY) && !(how->flags & O_RDWR))) {
        errno = EINVAL; return -1;
    }
    return 0;
}

static int safe_open(struct open_request *op)
{
    if (validate_how(&op->how) < 0) return -1;
    struct open_how inspect = {
        .flags = O_PATH | O_CLOEXEC | (op->how.flags & (O_NOFOLLOW | O_DIRECTORY)),
        .resolve = op->how.resolve | RESOLVE_NO_MAGICLINKS
    };
    int base = op->base < 0 ? AT_FDCWD : op->base;
    int object = (int)syscall(SYS_openat2, base, op->path, &inspect, sizeof(inspect));
    if (object >= 0) {
        struct statfs fs;
        struct stat st;
        if (fstatfs(object, &fs) < 0 || fstat(object, &st) < 0) {
            int saved = errno; close(object); errno = saved; return -1;
        }
        if ((unsigned long)fs.f_type == PROC_SUPER_MAGIC) {
            close(object); errno = EOPNOTSUPP; return -1;
        }
        if (op->how.flags & O_PATH) return object;
        if (S_ISLNK(st.st_mode)) { close(object); errno = ELOOP; return -1; }
        if ((op->how.flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
            close(object); errno = EEXIST; return -1;
        }
        if ((op->how.flags & O_CREAT) && S_ISDIR(st.st_mode)) {
            close(object); errno = EISDIR; return -1;
        }
        /* Use only our fixed, inspected object. Concurrent rename/symlink
         * changes cannot redirect this open into the trusted worker's procfs.
         * Landlock still authorizes the actual file read/write/truncate. */
        char own_fd[80];
        snprintf(own_fd, sizeof(own_fd), "/proc/self/fd/%d", object);
        struct open_how actual = op->how;
        actual.flags |= O_CLOEXEC;
        actual.flags &= ~(uint64_t)O_NOFOLLOW;
        if (actual.flags & O_CREAT) {
            actual.flags &= ~(uint64_t)(O_CREAT | O_EXCL);
            actual.mode = 0;
        }
        actual.resolve = 0;
        int fd = (int)syscall(SYS_openat2, AT_FDCWD, own_fd, &actual, sizeof(actual));
        int saved = errno; close(object); errno = saved; return fd;
    }
    if (errno != ENOENT || !(op->how.flags & O_CREAT)) return -1;
    /* A missing final component is created below an independently pinned
     * directory. A concurrently installed symlink is refused, not followed. */
    char parent[PATH_MAX], name[PATH_MAX];
    const char *slash = strrchr(op->path, '/');
    if (!slash) {
        snprintf(parent, sizeof(parent), ".");
        snprintf(name, sizeof(name), "%s", op->path);
    } else {
        size_t length = (size_t)(slash - op->path);
        if (!length) length = 1;
        memcpy(parent, op->path, length); parent[length] = 0;
        snprintf(name, sizeof(name), "%s", slash + 1);
    }
    if (!name[0] || !strcmp(name, ".") || !strcmp(name, "..")) { errno = ENOENT; return -1; }
    inspect.flags = O_PATH | O_DIRECTORY | O_CLOEXEC;
    int directory = (int)syscall(SYS_openat2, base, parent, &inspect, sizeof(inspect));
    if (directory < 0) return -1;
    struct statfs fs;
    if (fstatfs(directory, &fs) < 0) { int saved = errno; close(directory); errno = saved; return -1; }
    if ((unsigned long)fs.f_type == PROC_SUPER_MAGIC) { close(directory); errno = EOPNOTSUPP; return -1; }
    struct open_how actual = op->how;
    actual.flags |= O_CLOEXEC | O_NOFOLLOW;
    actual.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    int fd = (int)syscall(SYS_openat2, directory, name, &actual, sizeof(actual));
    int saved = errno; close(directory); errno = saved; return fd;
}

static void perform_open(const struct config *cfg, int listener,
                          const struct seccomp_notif *request, struct open_request *op)
{
    int audit = cfg->state ? cfg->state->audit_fd : -1;
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) < 0) {
        (void)broker_event(cfg, "file_open_setup_error", request, op->path, -1, errno);
        respond_error(listener, request, EIO); worker_exit(cfg, 1);
    }
    char error[256];
    /* security_restrict_files consumes the same startup-pinned policy roots
     * as the payload. Keep those inherited descriptors until installation;
     * never re-open a mutable rule pathname in this worker. */
    if (security_restrict_files(cfg, error, sizeof(error)) < 0) {
        int saved = errno ? errno : EACCES;
        (void)broker_event(cfg, "file_open_setup_error", request, op->path, -1, saved);
        respond_error(listener, request, saved); worker_exit(cfg, 1);
    }
    if (close_other_fds(listener, audit, op->base) < 0) {
        (void)broker_event(cfg, "file_open_setup_error", request, op->path, -1, errno);
        respond_error(listener, request, EIO); worker_exit(cfg, 1);
    }
    umask(op->mask);
    if (valid_id(listener, request->id) < 0) {
        (void)broker_event(cfg, "file_open_cancelled", request, op->path, -1, errno);
        worker_exit(cfg, 0);
    }
    /* /proc/self and magic FD links would otherwise refer to the trusted
     * worker. Never inject procfs descriptors or follow magic links. The
     * additional resolve constraint is an explicit audit-mode restriction. */
    bool target_cloexec = (op->how.flags & O_CLOEXEC) != 0;
    int fd = safe_open(op);
    int saved = fd < 0 ? errno : 0;
    if (fd >= 0) {
        struct statfs fs;
        int stat_result = fstatfs(fd, &fs);
        if (stat_result < 0 || (unsigned long)fs.f_type == PROC_SUPER_MAGIC) {
            saved = stat_result < 0 ? errno : EOPNOTSUPP;
            close(fd); fd = -1;
        }
    }
    if (broker_event(cfg, "file_open_result", request, op->path, fd, saved) < 0) {
        if (fd >= 0) close(fd);
        respond_error(listener, request, EIO); worker_exit(cfg, 1);
    }
    if (fd < 0) { respond_error(listener, request, saved); worker_exit(cfg, 0); }
    struct seccomp_notif_addfd add = {.id = request->id, .srcfd = (unsigned)fd,
        .newfd_flags = target_cloexec ? O_CLOEXEC : 0, .flags = SECCOMP_ADDFD_FLAG_SEND};
    int injected;
    do { injected = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add); }
    while (injected < 0 && errno == EINTR);
    saved = injected < 0 ? errno : 0;
    int file_flags = fcntl(fd, F_GETFL);
    struct stat object_stat;
    bool native_fallback = injected < 0 && saved == EBADF && file_flags >= 0 &&
        (file_flags & O_PATH) && fstat(fd, &object_stat) == 0;
    close(fd);
    int logged = broker_event(cfg, "file_open_delivery", request, op->path, injected, saved);
    if (logged < 0) {
        /* A successful atomic ADDFD+SEND cannot be revoked. audit_failed in
         * shared state tells the monitor to stop the run immediately. */
        worker_exit(cfg, 1);
    }
    if (native_fallback) {
        /* Older kernels use fget(), not fget_raw(), in ADDFD and cannot
         * transfer O_PATH handles. No descriptor was installed on EBADF.
         * Continue only under the payload's existing kernel Landlock policy;
         * this is NOT pathname-snapshot authorization or a success result. */
        if (broker_event(cfg, "file_open_native_fallback", request, op->path, 0, EBADF) < 0) {
            respond_error(listener, request, EIO); worker_exit(cfg, 1);
        }
        if (cfg->state) {
            ++cfg->state->continued;
            ++cfg->state->native_open_fallbacks;
        }
        struct seccomp_notif_resp response = {.id = request->id,
            .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE};
        int rc;
        do { rc = ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response); }
        while (rc < 0 && errno == EINTR);
        worker_exit(cfg, 0);
    }
    if (injected < 0 && saved != ENOENT) respond_error(listener, request, saved);
    worker_exit(cfg, 0);
}

int filebroker_handle(const struct config *cfg, int listener,
                      const struct seccomp_notif *request,
                      struct seccomp_notif_resp *response)
{
    int nr = request->data.nr;
    bool supported = nr == SYS_openat || nr == SYS_openat2;
#ifdef SYS_open
    supported = supported || nr == SYS_open;
#endif
#ifdef SYS_creat
    supported = supported || nr == SYS_creat;
#endif
    if (!supported) return -2;
    *response = (struct seccomp_notif_resp){.id = request->id};
    filebroker_reap();
    size_t slot;
    for (slot = 0; slot < CINCTA_FILE_MAX_WORKERS && workers[slot] > 0; ++slot) {}
    if (slot == CINCTA_FILE_MAX_WORKERS) { response->error = -EAGAIN; return 0; }
    struct open_request op;
    if (capture_request(listener, request, &op) < 0) { response->error = -errno; return 0; }
    if (broker_event(cfg, "file_open_snapshot", request, op.path, (long long)op.how.flags, 0) < 0) {
        if (op.base >= 0) close(op.base);
        return -1;
    }
    /* Account before the child can perform any filesystem operation. Reserve
     * in the parent to cover a child killed immediately after fork as well. */
    if (cfg->state) ++cfg->state->delivery_pending;
    pid_t worker = fork();
    if (worker < 0) {
        if (cfg->state) --cfg->state->delivery_pending;
        int saved = errno; if (op.base >= 0) close(op.base); response->error = -saved; return 0;
    }
    if (worker == 0) perform_open(cfg, listener, request, &op);
    workers[slot] = worker;
    if (op.base >= 0) close(op.base);
    return 1;
}
