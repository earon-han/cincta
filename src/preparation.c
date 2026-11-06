#define _GNU_SOURCE
#include "preparation.h"
#include "cincta.h"
#include "resources.h"
#include "workspace.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct preparation_shared {
    struct workspace_ctx workspace;
    struct resource_ctx resources;
    char container[PATH_MAX];
    dev_t device;
    ino_t inode;
    bool created;
    _Atomic unsigned request_serial;
    char cgroup_parent[PATH_MAX];
    unsigned memory_mb, pids, cpu_percent, cpu_ms;
};

/* A command is a single PIPE_BUF-sized write. Large policy data lives in the
 * shared request slot, committed before R with a release/acquire atomic. */
struct command { unsigned char operation; pid_t monitor; };
struct reply { int result; int error; char message[512]; };
_Static_assert(sizeof(struct command) <= PIPE_BUF, "preparation command must be atomic");
_Static_assert(sizeof(struct reply) <= PIPE_BUF, "preparation reply must be atomic");

static int errorf(char *error, size_t size, const char *fmt, ...)
{
    int saved = errno;
    va_list args;
    va_start(args, fmt);
    if (size) vsnprintf(error, size, fmt, args);
    va_end(args);
    errno = saved;
    return -1;
}

static int high_pipe(int fds[2])
{
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) < 0) return -1;
    for (int i = 0; i < 2; ++i) {
        if (fds[i] < 3) {
            int replacement = fcntl(fds[i], F_DUPFD_CLOEXEC, 3);
            if (replacement < 0) { int saved = errno; close(fds[0]); close(fds[1]); errno = saved; return -1; }
            close(fds[i]); fds[i] = replacement;
        }
    }
    return 0;
}

static int close_except(int a, int b, int c)
{
    int keep[3] = {a, b, c};
    for (int i = 0; i < 3; ++i)
        for (int j = i + 1; j < 3; ++j)
            if (keep[j] < keep[i]) { int swap = keep[i]; keep[i] = keep[j]; keep[j] = swap; }
    unsigned first = 3;
    for (int i = 0; i < 3; ++i) {
        if (keep[i] < 3) continue;
        unsigned fd = (unsigned)keep[i];
        if (first < fd && syscall(SYS_close_range, first, fd - 1, 0) < 0) return -1;
        first = fd + 1;
    }
    return (int)syscall(SYS_close_range, first, UINT_MAX, 0);
}

static int send_reply(int fd, int result, const char *message)
{
    struct reply reply = {.result = result, .error = result < 0 ? errno : 0};
    if (message) snprintf(reply.message, sizeof(reply.message), "%s", message);
    ssize_t sent;
    do { sent = write(fd, &reply, sizeof(reply)); } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)sizeof(reply) ? 0 : -1;
}

static ssize_t command_write(int fd, const void *data, size_t size)
{
    /* CLI is single-threaded during preparation. A failed guardian must cause
     * a checked RPC error, not terminate the CLI through an ambient SIGPIPE. */
    struct sigaction ignore = {.sa_handler = SIG_IGN}, previous;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, &previous) < 0) return -1;
    ssize_t result;
    do { result = write(fd, data, size); } while (result < 0 && errno == EINTR);
    int saved = errno;
    if (sigaction(SIGPIPE, &previous, NULL) < 0 && result >= 0) { saved = errno; result = -1; }
    errno = saved;
    return result;
}

static int receive_reply(struct preparation_guard *guard, char *error, size_t size)
{
    struct reply reply;
    for (;;) {
        ssize_t received = read(guard->status_fd, &reply, sizeof(reply));
        if (received == (ssize_t)sizeof(reply)) {
            if (reply.result < 0) { errno = reply.error; return errorf(error, size, "%s", reply.message); }
            return 0;
        }
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && errno == EAGAIN) {
            struct pollfd p = {.fd = guard->status_fd, .events = POLLIN | POLLHUP};
            if (poll(&p, 1, -1) < 0 && errno != EINTR) return errorf(error, size, "wait preparation guardian: %s", strerror(errno));
            continue;
        }
        errno = EPROTO;
        return errorf(error, size, "preparation guardian ended without a complete reply");
    }
}

static int open_container(const struct preparation_guard *guard)
{
    if (!guard->shared || !guard->shared->created) return -2;
    const struct preparation_shared *shared = guard->shared;
    int fd = open(shared->container, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? -2 : -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_dev != shared->device || st.st_ino != shared->inode || st.st_uid != geteuid()) {
        close(fd); errno = ESTALE; return -1;
    }
    return fd;
}

int preparation_cleanup_container(struct preparation_guard *guard, bool keep,
                                  char *error, size_t size)
{
    if (keep || !guard || !guard->shared) return 0;
    int fd = open_container(guard);
    if (fd == -2) return 0;
    if (fd < 0) return errorf(error, size, "preparation container identity changed: %s", strerror(errno));
    int result = rmdir(guard->shared->container);
    int saved = errno; close(fd); errno = saved;
    if (result < 0 && errno != ENOENT) return errorf(error, size, "remove empty preparation container '%s': %s", guard->shared->container, strerror(errno));
    return 0;
}

/* Cancellation may interrupt workspace_prepare before ctx.prepared is set.
 * The whole enclosing container was created and pinned by this guardian, so
 * its contents are ours; no path prefix/ctime/UID ownership guess is needed. */
static int open_removable_dir(int parent, const char *name)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 || errno != EACCES) return fd;
    int pin = openat(parent, name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pin < 0) return -1;
    struct stat st; char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", pin);
    if (fstat(pin, &st) < 0 || st.st_uid != geteuid() || chmod(path, 0700) < 0) { close(pin); return -1; }
    fd = openat(pin, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(pin);
    return fd;
}

static int remove_contents(int fd, unsigned depth)
{
    if (depth > 132) { errno = ELOOP; return -1; }
    if (fchmod(fd, 0700) < 0) return -1;
    int duplicate = dup(fd);
    if (duplicate < 0) return -1;
    DIR *directory = fdopendir(duplicate);
    if (!directory) { close(duplicate); return -1; }
    rewinddir(directory);
    int rc = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) rc = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) { rc = -1; break; }
        if (S_ISDIR(st.st_mode)) {
            int child = open_removable_dir(fd, entry->d_name);
            if (child < 0) { rc = -1; break; }
            rc = remove_contents(child, depth + 1);
            int saved = errno; close(child); errno = saved;
            if (!rc) rc = unlinkat(fd, entry->d_name, AT_REMOVEDIR);
        } else rc = unlinkat(fd, entry->d_name, 0);
        if (rc < 0) break;
    }
    int saved = errno; closedir(directory); errno = saved;
    return rc;
}

static int cancelled_cleanup(struct preparation_guard *guard, char *error, size_t size)
{
    struct preparation_shared *shared = guard->shared;
    int result = 0;
    if (shared->resources.enabled && !shared->resources.removed) {
        if (resource_kill(&shared->resources, error, size) < 0) result = -1;
        for (unsigned attempt = 0; attempt < 200; ++attempt) {
            if (resource_finish(&shared->resources, error, size) == 0) break;
            if (errno != EBUSY || attempt == 199) { result = -1; break; }
            struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
        }
    }
    int fd = open_container(guard);
    if (fd >= 0) {
        int removed = remove_contents(fd, 0);
        int saved = errno; close(fd); errno = saved;
        if (removed < 0) { errorf(error, size, "discard cancelled preparation container: %s", strerror(errno)); result = -1; }
        else if (preparation_cleanup_container(guard, false, error, size) < 0) result = -1;
        else { shared->workspace.prepared = false; shared->workspace.retained = false; }
    } else if (fd != -2) result = -1;
    return result;
}

static int create_container(struct preparation_guard *guard, const char *parent,
                             char *error, size_t size)
{
    char canonical[PATH_MAX];
    if (!parent) parent = "/tmp";
    if (*parent != '/') { errno = EINVAL; return errorf(error, size, "preparation parent must be absolute"); }
    if (!realpath(parent, canonical)) return errorf(error, size, "resolve preparation parent: %s", strerror(errno));
    int written = snprintf(guard->shared->container, sizeof(guard->shared->container),
        "%s%scincta-preparation-XXXXXX", canonical, !strcmp(canonical, "/") ? "" : "/");
    if (written < 0 || (size_t)written >= sizeof(guard->shared->container)) { errno = ENAMETOOLONG; return errorf(error, size, "preparation parent too long"); }
    if (!mkdtemp(guard->shared->container)) return errorf(error, size, "create preparation container: %s", strerror(errno));
    int fd = open(guard->shared->container, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0) {
        int saved = errno; if (fd >= 0) close(fd); rmdir(guard->shared->container); errno = saved;
        return errorf(error, size, "identify preparation container: %s", strerror(errno));
    }
    close(fd);
    guard->shared->device = st.st_dev; guard->shared->inode = st.st_ino;
    guard->shared->created = true;
    return 0;
}

static int guardian(struct preparation_guard *guard, int control, int status,
                    pid_t parent_pid, const char *requested_parent)
{
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGPIPE, &ignore, NULL); sigaction(SIGTERM, &ignore, NULL);
    sigaction(SIGINT, &ignore, NULL); sigaction(SIGHUP, &ignore, NULL);
    sigset_t mask; sigemptyset(&mask); sigprocmask(SIG_SETMASK, &mask, NULL);
    if (setpgid(0, 0) < 0) { send_reply(status, -1, "isolate preparation guardian process group"); return 125; }
    int parent_fd = (int)syscall(SYS_pidfd_open, parent_pid, 0);
    if (parent_fd >= 0 && parent_fd < 3) {
        int high = fcntl(parent_fd, F_DUPFD_CLOEXEC, 3); close(parent_fd); parent_fd = high;
    }
    if (parent_fd < 0 || getppid() != parent_pid) { if (parent_fd >= 0) close(parent_fd); return 125; }
    if (close_except(control, status, parent_fd) < 0) { send_reply(status, -1, "sanitize guardian descriptors"); return 125; }
    char error[512] = {0};
    if (create_container(guard, requested_parent, error, sizeof(error)) < 0) { send_reply(status, -1, error); return 125; }
    if (send_reply(status, 0, "") < 0) {
        (void)cancelled_cleanup(guard, error, sizeof(error)); return 125;
    }
    bool resource_requested = false;
    for (;;) {
        struct pollfd waiting[2] = {{.fd = control, .events = POLLIN | POLLHUP},
                                    {.fd = parent_fd, .events = POLLIN}};
        int ready = poll(waiting, 2, -1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        bool ended = waiting[1].revents != 0;
        /* Drain control before acting on parent death/EOF: D may already be
         * buffered and monitor may own the artifacts even if CLI just died. */
        for (;;) {
            struct command cmd;
            ssize_t n = read(control, &cmd, sizeof(cmd));
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && errno == EAGAIN) break;
            if (n != (ssize_t)sizeof(cmd)) { ended = true; break; }
            if (cmd.operation == 'D') {
                int monitor = cmd.monitor > 0 ? (int)syscall(SYS_pidfd_open, cmd.monitor, 0) : -1;
                if (monitor < 0) {
                    errno = ESRCH; send_reply(status, -1, "handover monitor identity unavailable");
                    continue;
                }
                close(monitor); send_reply(status, 0, ""); close(parent_fd); return 0;
            }
            if (cmd.operation == 'F') {
                int rc = resource_finish(&guard->shared->resources, error, sizeof(error));
                if (preparation_cleanup_container(guard, guard->shared->workspace.prepared ||
                    guard->shared->workspace.retained, error, sizeof(error)) < 0) rc = -1;
                send_reply(status, rc, error); close(parent_fd); return rc < 0 ? 125 : 0;
            }
            if (cmd.operation == 'R') {
                if (ended) break;
                if (resource_requested) { errno = EALREADY; send_reply(status, -1, "resource preparation is one-shot"); continue; }
                resource_requested = true;
                (void)atomic_load_explicit(&guard->shared->request_serial, memory_order_acquire);
                struct config cfg = {.cgroup_parent = guard->shared->cgroup_parent[0] ? guard->shared->cgroup_parent : NULL,
                    .tree_memory_mb = guard->shared->memory_mb, .tree_pids = guard->shared->pids,
                    .tree_cpu_percent = guard->shared->cpu_percent, .tree_cpu_ms = guard->shared->cpu_ms};
                int rc = resource_prepare(&cfg, &guard->shared->resources, error, sizeof(error));
                if (send_reply(status, rc, error) < 0) { ended = true; break; }
            } else { errno = EPROTO; send_reply(status, -1, "invalid preparation command"); ended = true; break; }
        }
        if (ended) break;
    }
    int rc = cancelled_cleanup(guard, error, sizeof(error));
    if (rc < 0) fprintf(stderr, "cincta: preparation cancellation cleanup failed: %s\n", error[0] ? error : strerror(errno));
    close(parent_fd);
    return rc < 0 ? 125 : 0;
}

static int reap_guard(struct preparation_guard *guard, char *error, size_t size)
{
    if (!guard->active) return 0;
    int status; pid_t waited;
    do { waited = waitpid(guard->pid, &status, 0); } while (waited < 0 && errno == EINTR);
    guard->active = false;
    if (guard->control_fd >= 0) close(guard->control_fd);
    if (guard->status_fd >= 0) close(guard->status_fd);
    guard->control_fd = guard->status_fd = -1;
    if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) return errorf(error, size, "preparation guardian failed");
    return 0;
}

static int command_send(struct preparation_guard *guard, unsigned char operation,
                         pid_t monitor, char *error, size_t size)
{
    if (!guard->active) { errno = EPIPE; return errorf(error, size, "preparation guardian unavailable"); }
    struct command cmd = {.operation = operation, .monitor = monitor};
    ssize_t written;
    written = command_write(guard->control_fd, &cmd, sizeof(cmd));
    if (written != (ssize_t)sizeof(cmd)) return errorf(error, size, "send preparation command: %s", strerror(errno));
    return receive_reply(guard, error, size);
}

int preparation_start(struct workspace_ctx **workspace, struct resource_ctx **resources,
                      const char *requested_parent, struct preparation_guard *guard,
                      char *error, size_t size)
{
    if (!workspace || !resources || !guard) { errno = EINVAL; return errorf(error, size, "preparation context pointers are required"); }
    memset(guard, 0, sizeof(*guard)); guard->control_fd = guard->status_fd = -1;
    struct sigaction defaults = {.sa_handler = SIG_DFL};
    sigemptyset(&defaults.sa_mask);
    if (sigaction(SIGCHLD, &defaults, NULL) < 0) return errorf(error, size, "prepare child reaping: %s", strerror(errno));
    guard->shared = mmap(NULL, sizeof(*guard->shared), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (guard->shared == MAP_FAILED) { guard->shared = NULL; return errorf(error, size, "map preparation state: %s", strerror(errno)); }
    memset(guard->shared, 0, sizeof(*guard->shared));
    int control[2], status[2];
    if (high_pipe(control) < 0) goto failed;
    if (high_pipe(status) < 0) { int saved = errno; close(control[0]); close(control[1]); errno = saved; goto failed; }
    pid_t parent_pid = getpid();
    guard->pid = fork();
    if (guard->pid < 0) { int saved = errno; close(control[0]); close(control[1]); close(status[0]); close(status[1]); errno = saved; goto failed; }
    if (guard->pid == 0) {
        close(control[1]); close(status[0]);
        _exit(guardian(guard, control[0], status[1], parent_pid, requested_parent));
    }
    close(control[0]); close(status[1]);
    guard->control_fd = control[1]; guard->status_fd = status[0]; guard->active = true;
    if (receive_reply(guard, error, size) < 0) {
        int saved = errno;
        close(guard->control_fd); guard->control_fd = -1;
        char ignored[128]; (void)reap_guard(guard, ignored, sizeof(ignored));
        munmap(guard->shared, sizeof(*guard->shared)); guard->shared = NULL;
        errno = saved; return -1;
    }
    *workspace = &guard->shared->workspace; *resources = &guard->shared->resources;
    return 0;
failed:;
    int saved = errno; munmap(guard->shared, sizeof(*guard->shared)); guard->shared = NULL; errno = saved;
    return errorf(error, size, "start preparation guardian: %s", strerror(errno));
}

const char *preparation_workspace_parent(const struct preparation_guard *guard)
{
    return guard && guard->shared && guard->shared->created ? guard->shared->container : NULL;
}

int preparation_resources(struct preparation_guard *guard, const struct config *cfg,
                          char *error, size_t size)
{
    if (!guard || !guard->shared || cfg->resources != &guard->shared->resources) {
        errno = EINVAL; return errorf(error, size, "resource preparation requires guardian-owned shared context");
    }
    if (cfg->cgroup_parent && strlen(cfg->cgroup_parent) >= sizeof(guard->shared->cgroup_parent)) {
        errno = ENAMETOOLONG; return errorf(error, size, "cgroup parent too long");
    }
    snprintf(guard->shared->cgroup_parent, sizeof(guard->shared->cgroup_parent), "%s", cfg->cgroup_parent ? cfg->cgroup_parent : "");
    guard->shared->memory_mb = cfg->tree_memory_mb; guard->shared->pids = cfg->tree_pids;
    guard->shared->cpu_percent = cfg->tree_cpu_percent; guard->shared->cpu_ms = cfg->tree_cpu_ms;
    atomic_fetch_add_explicit(&guard->shared->request_serial, 1, memory_order_release);
    return command_send(guard, 'R', 0, error, size);
}

int preparation_handover(struct preparation_guard *guard, pid_t monitor,
                         char *error, size_t size)
{
    if (!guard || !guard->shared) return 0;
    if (command_send(guard, 'D', monitor, error, size) < 0) return -1;
    if (reap_guard(guard, error, size) < 0) return -1;
    guard->handed_over = true;
    return 0;
}

int preparation_finish(struct preparation_guard *guard, char *error, size_t size)
{
    if (!guard || !guard->shared) return 0;
    int rc = 0;
    if (guard->active) {
        if (command_send(guard, 'F', 0, error, size) < 0) rc = -1;
        if (guard->control_fd >= 0) { close(guard->control_fd); guard->control_fd = -1; }
        if (reap_guard(guard, error, size) < 0) rc = -1;
    }
    bool keep = guard->shared->workspace.prepared || guard->shared->workspace.retained;
    if (preparation_cleanup_container(guard, keep, error, size) < 0) rc = -1;
    munmap(guard->shared, sizeof(*guard->shared)); guard->shared = NULL;
    return rc;
}
