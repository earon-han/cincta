#define _GNU_SOURCE
#include "cincta.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int result_open(const struct config *cfg);
int result_get_fd(void);
void result_close(void);
int result_reset(void);
void result_set_phases(uint64_t setup, uint64_t run, uint64_t cleanup);
static volatile sig_atomic_t caught;
static void on_signal(int sig) { caught = sig; }

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Close arbitrary inherited descriptors, including ones above our new rlimit. */
static int close_fds_except(int keep, int extra)
{
#ifdef SYS_close_range
    int first = keep, last = extra;
    if (last < 3) last = first;
    if (first > last) { int swap = first; first = last; last = swap; }
    if ((first <= 3 || syscall(SYS_close_range, 3u, (unsigned)first - 1, 0) == 0) &&
        (last <= first + 1 || syscall(SYS_close_range, (unsigned)first + 1, (unsigned)last - 1, 0) == 0) &&
        syscall(SYS_close_range, (unsigned)last + 1, UINT_MAX, 0) == 0) return 0;
#endif
    /* close_range exists on every supported upstream kernel. Fail closed if a
     * surrounding policy forbids it, rather than leak descriptors silently. */
    return -1;
}

struct setup_message { int code; uint64_t timestamp; char stage[24]; char message[256]; };

static void child_error(int fd, int code, const char *stage, const char *message)
{
    struct setup_message m = { .code = code };
    snprintf(m.stage, sizeof(m.stage), "%s", stage);
    snprintf(m.message, sizeof(m.message), "%s", message);
    ssize_t n;
    do { n = write(fd, &m, sizeof(m)); } while (n < 0 && errno == EINTR);
    _exit(code);
}

static int limit_set(int resource, rlim_t value)
{
    struct rlimit lim = {value, value};
    return setrlimit(resource, &lim);
}

/* These PIDs are our direct children. A child remains pinned (alive or zombie)
 * until this single-threaded monitor reaps it, so numeric kill cannot target
 * an unrelated recycled PID. Repeating handles newly adopted grandchildren. */
static int signal_children(bool send_signal)
{
    char path[96];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)getpid());
    FILE *f = fopen(path, "re");
    if (!f) return -1;
    long pid;
    while (fscanf(f, "%ld", &pid) == 1) {
        if (send_signal && pid > 0 && pid <= INT_MAX) kill((pid_t)pid, SIGKILL);
    }
    int failed = ferror(f);
    fclose(f);
    return failed ? -1 : 0;
}

/* execvp/execvpe run /bin/sh on ENOEXEC. Preserve the CLI's literal argv
 * contract: search explicit PATH, but never add an implicit interpreter. */
static void exec_command(const struct config *cfg)
{
    const char *name = cfg->command[0];
    if (strchr(name, '/')) { execve(name, cfg->command, (char *const *)cfg->env); return; }
    const char *path = getenv("PATH");
    if (!path) path = "/usr/bin:/bin";
    bool denied = false;
    for (;;) {
        const char *end = strchr(path, ':');
        size_t length = end ? (size_t)(end - path) : strlen(path);
        char candidate[PATH_MAX];
        int n = length ? snprintf(candidate, sizeof(candidate), "%.*s/%s", (int)length, path, name)
                       : snprintf(candidate, sizeof(candidate), "%s", name);
        if (n < 0 || (size_t)n >= sizeof(candidate)) { errno = ENAMETOOLONG; return; }
        execve(candidate, cfg->command, (char *const *)cfg->env);
        if (errno == EACCES) denied = true;
        else if (errno != ENOENT && errno != ENOTDIR) return;
        if (!end) break;
        path = end + 1;
    }
    errno = denied ? EACCES : ENOENT;
}

static void payload(const struct config *cfg, int error_fd)
{
    struct capabilities caps = {0};
    char message[256];
    struct sigaction sa = {.sa_handler = SIG_DFL};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL); sigaction(SIGPIPE, &sa, NULL);
    sigset_t empty;
    sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);
    if (setpgid(0, 0) < 0) child_error(error_fd, 125, "process_group", strerror(errno));
    if (close_fds_except(error_fd, -1) < 0) child_error(error_fd, 125, "fd_cleanup", strerror(errno));
    if (limit_set(RLIMIT_CORE, 0) < 0 ||
        limit_set(RLIMIT_AS, (rlim_t)cfg->memory_mb * 1024 * 1024) < 0 ||
        limit_set(RLIMIT_CPU, cfg->cpu_seconds) < 0 ||
        limit_set(RLIMIT_NPROC, cfg->processes) < 0 ||
        limit_set(RLIMIT_NOFILE, cfg->nofile) < 0)
        child_error(error_fd, 125, "limits", strerror(errno));
    if (chdir(cfg->cwd) < 0) child_error(error_fd, 125, "cwd", strerror(errno));
    if (security_apply(cfg, &caps, message, sizeof(message)) < 0)
        child_error(error_fd, 125, "security", message);
    struct setup_message ready = {.code = 0, .timestamp = now_ms(), .stage = "running"};
    if (write(error_fd, &ready, sizeof(ready)) != (ssize_t)sizeof(ready))
        child_error(error_fd, 125, "handshake", "cannot report installed protections");
    /* The executable search and exec use the same explicit environment. */
    extern char **environ;
    environ = (char **)cfg->env;
    exec_command(cfg);
    int saved = errno;
    child_error(error_fd, saved == ENOENT ? 127 : 126, "exec", strerror(saved));
}

static int finish(const struct config *cfg, const struct capabilities *caps,
                  const char *status, const char *stage, const char *message,
                  int code, int sig, bool timeout, bool cancel, bool clean,
                  uint64_t start)
{
    if (result_write(cfg, caps, status, stage, message, code, sig, timeout, cancel,
                     clean, now_ms() - start) < 0) {
        fprintf(stderr, "cincta: result write failed: %s\n", strerror(errno));
        return 125;
    }
    if (!clean) {
        fprintf(stderr, "cincta: descendant cleanup incomplete\n");
        return 125;
    }
    return code;
}

/* Trusted monitor is the direct parent of the process-group leader, remains
 * outside its group, and adopts grandchildren. EOF on control means CLI died.
 * Keep the leader zombie until killpg to prevent its PID/PGID being recycled. */
static int monitor_run(const struct config *cfg, int control)
{
    uint64_t start = now_ms();
    struct capabilities caps = {0};
    int errors[2];
    pid_t child;
    if (close_fds_except(control, result_get_fd()) < 0) {
        fprintf(stderr, "cincta: monitor descriptor cleanup failed\n"); return 125;
    }
    if (security_probe(&caps) < 0 || prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
        return finish(cfg, &caps, "setup_error", "probe", strerror(errno), 125, 0, false, false, true, start);
    if (caps.landlock_abi < (cfg->compat ? 3 : 6) || !caps.seccomp)
        return finish(cfg, &caps, "setup_error", "capabilities",
            "requires seccomp and Landlock ABI >=6 (or explicit --compat with ABI >=3)",
            125, 0, false, false, true, start);
    if (signal_children(false) < 0)
        return finish(cfg, &caps, "setup_error", "procfs", "readable procfs children is required for cleanup",
            125, 0, false, false, true, start);
    if (pipe2(errors, O_CLOEXEC | O_NONBLOCK) < 0)
        return finish(cfg, &caps, "setup_error", "pipe", strerror(errno), 125, 0, false, false, true, start);
    child = fork();
    if (child < 0) {
        close(errors[0]); close(errors[1]);
        return finish(cfg, &caps, "setup_error", "fork", strerror(errno), 125, 0, false, false, true, start);
    }
    if (child == 0) payload(cfg, errors[1]);
    close(errors[1]);
    /* Parent and child both set the same group, closing the launch race. */
    int pgerr = setpgid(child, child);
    if (pgerr < 0 && errno != EACCES && errno != ESRCH) {
        kill(child, SIGKILL);
    }
    bool timed_out = false, cancelled = false;
    int cancel_signal = 0;
    for (;;) {
        siginfo_t info = {0};
        if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid) break;
        if (caught) { cancelled = true; cancel_signal = caught; break; }
        uint64_t elapsed = now_ms() - start;
        if (cfg->timeout_ms && elapsed >= cfg->timeout_ms) { timed_out = true; break; }
        struct pollfd p = {.fd = control, .events = POLLIN | POLLHUP};
        int ready = poll(&p, 1, 10);
        if (ready > 0) {
            unsigned char sig;
            ssize_t n = read(control, &sig, 1);
            if (n == 0 || n == 1) {
                cancelled = true;
                cancel_signal = n == 1 ? (int)sig : SIGTERM;
                break;
            }
        } else if (ready < 0 && errno != EINTR) {
            cancelled = true; cancel_signal = SIGTERM; break;
        }
    }
    /* Cancel is immediate SIGKILL: no grace interval in which children can
     * continue mutating files or forking. Also kill background jobs on exit. */
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    uint64_t cleanup_start = now_ms();
    bool clean = false, have_status = false;
    int status = 0;
    while (now_ms() - cleanup_start < 2000) {
        if (signal_children(true) < 0) break;
        int st;
        /* __WALL also reaps adversarial clone children using exit_signal=0. */
        pid_t pid = waitpid(-1, &st, WNOHANG | __WALL);
        if (pid > 0) {
            if (pid == child) { status = st; have_status = true; }
            continue;
        }
        if (pid < 0 && errno == ECHILD) { clean = true; break; }
        if (pid < 0 && errno != EINTR) break;
        /* Never signal this numeric group after reaping its leader: it could
         * have become empty and the numeric ID could then be recycled. */
        if (!have_status) kill(-child, SIGKILL);
        struct timespec ts = {0, 10000000}; nanosleep(&ts, NULL);
    }
    struct setup_message m = {0}, next;
    bool active = false;
    uint64_t ready_ms = cleanup_start;
    ssize_t bytes;
    for (;;) {
        do { bytes = read(errors[0], &next, sizeof(next)); } while (bytes < 0 && errno == EINTR);
        if (bytes != (ssize_t)sizeof(next)) break;
        if (next.code == 0) { active = true; ready_ms = next.timestamp; }
        else m = next;
    }
    close(errors[0]); close(control);
    result_set_phases(ready_ms - start, cleanup_start - ready_ms, now_ms() - cleanup_start);
    if (m.code) {
        fprintf(stderr, "cincta: %s: %s\n", m.stage, m.message);
        return finish(cfg, &caps, "setup_error", m.stage, m.message, m.code, 0, timed_out, cancelled, clean, start);
    }
    if (timed_out) return finish(cfg, &caps, "timeout", active ? "running" : "setup", "wall timeout", 124, SIGKILL, true, false, clean, start);
    if (cancelled) return finish(cfg, &caps, "cancelled", active ? "running" : "setup", "caller cancelled or exited",
        128 + cancel_signal, cancel_signal, false, true, clean, start);
    if (!have_status) return finish(cfg, &caps, "setup_error", "wait", "missing child status", 125, 0, false, false, clean, start);
    if (WIFSIGNALED(status)) return finish(cfg, &caps, "signal", active ? "running" : "setup", "command terminated by signal",
        128 + WTERMSIG(status), WTERMSIG(status), false, false, clean, start);
    if (!active) return finish(cfg, &caps, "setup_error", "handshake", "child exited before protection confirmation",
        125, 0, false, false, clean, start);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 125;
    return finish(cfg, &caps, code ? "exit" : "ok", "running", "", code, 0, false, false, clean, start);
}

int supervise(const struct config *cfg)
{
    int control[2], status;
    /* Keep control and result descriptors out of the stdio slots. */
    for (int fd = 0; fd < 3; ++fd) {
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
            int replacement = open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY);
            if (replacement != fd) { if (replacement >= 0) close(replacement); return 125; }
        }
    }
    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL); sigaction(SIGHUP, &sa, NULL);
    struct sigaction ign = {.sa_handler = SIG_IGN};
    sigaction(SIGPIPE, &ign, NULL);
    struct sigaction dfl = {.sa_handler = SIG_DFL};
    sigaction(SIGCHLD, &dfl, NULL);
    sigset_t empty;
    sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);
    /* pidfd follows the calling process, not just the spawning thread (the
     * latter would cause spurious cancellation with PR_SET_PDEATHSIG). */
    pid_t caller = getppid();
    /* A container's PID 1 has no visible parent (getppid()==0). Its runtime
     * cancels it with signals; there is no in-namespace caller to watch. */
    int caller_fd = caller > 0 ? (int)syscall(SYS_pidfd_open, caller, 0) : -1;
    if (caller > 0 && caller_fd < 0) { perror("cincta: caller pidfd"); return 125; }
    if (getppid() != caller) caught = SIGTERM;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0 || signal_children(false) < 0) {
        close(caller_fd); perror("cincta: recovery setup"); return 125;
    }
    if (result_open(cfg) < 0) {
        close(caller_fd); fprintf(stderr, "cincta: cannot create result: %s\n", strerror(errno)); return 125;
    }
    if (pipe2(control, O_CLOEXEC) < 0) { close(caller_fd); perror("cincta: pipe"); return 125; }
    pid_t monitor = fork();
    if (monitor < 0) { close(caller_fd); close(control[0]); close(control[1]); perror("cincta: fork"); return 125; }
    if (monitor == 0) {
        close(control[1]);
        _exit(monitor_run(cfg, control[0]));
    }
    close(control[0]);
    for (;;) {
        if (caught) {
            unsigned char sig = (unsigned char)caught;
            caught = 0;
            ssize_t sent = write(control[1], &sig, 1);
            if (sent < 0 && errno == EINTR) caught = sig;
        }
        pid_t got = waitpid(monitor, &status, WNOHANG);
        if (got == monitor) break;
        if (got < 0 && errno != EINTR) { close(caller_fd); close(control[1]); return 125; }
        struct pollfd p = {.fd = caller_fd, .events = POLLIN};
        if (poll(&p, 1, 10) > 0) {
            caught = SIGTERM;
            close(caller_fd); caller_fd = -1;
        }
    }
    close(control[1]);
    if (caller_fd >= 0) close(caller_fd);
    int residual_status;
    pid_t residual;
    do { residual = waitpid(-1, &residual_status, WNOHANG | __WALL); } while (residual < 0 && errno == EINTR);
    if (!WIFEXITED(status) || residual >= 0 || errno != ECHILD) {
        /* If the monitor alone crashes, adopted descendants are now direct
         * children of this CLI. Reap them using the same pinned-child rule. */
        uint64_t recovery = now_ms();
        bool clean = false;
        while (now_ms() - recovery < 2000) {
            if (signal_children(true) < 0) break;
            int st;
            pid_t got = waitpid(-1, &st, WNOHANG | __WALL);
            if (got > 0) continue;
            if (got < 0 && errno == ECHILD) { clean = true; break; }
            struct timespec ts = {0, 10000000}; nanosleep(&ts, NULL);
        }
        struct capabilities caps = {0};
        if (result_reset() < 0) { result_close(); return 125; }
        return finish(cfg, &caps, "setup_error", "monitor", "trusted monitor terminated unexpectedly",
            125, WIFSIGNALED(status) ? WTERMSIG(status) : 0, false, false, clean, recovery);
    }
    result_close();
    return WIFEXITED(status) ? WEXITSTATUS(status) : 125;
}
