#define _GNU_SOURCE
#include "cincta.h"
#include "broker.h"
#include "network.h"
#include "resources.h"
#include "workspace.h"
#include "preparation.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
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
static int close_fds_preserve(const int *keep, size_t count)
{
    int ordered[CINCTA_MAX_RULES + 4]; size_t n = 0;
    for (size_t i = 0; i < count; ++i) if (keep[i] >= 3) {
        if (n == CINCTA_MAX_RULES + 4) { errno = E2BIG; return -1; }
        ordered[n++] = keep[i];
    }
    for (size_t i = 0; i < n; ++i) for (size_t j = i + 1; j < n; ++j)
        if (ordered[j] < ordered[i]) { int t = ordered[j]; ordered[j] = ordered[i]; ordered[i] = t; }
    unsigned first = 3;
    for (size_t i = 0; i < n; ++i) {
        if ((unsigned)ordered[i] < first) continue;
        if ((unsigned)ordered[i] > first && syscall(SYS_close_range, first, (unsigned)ordered[i] - 1, 0) < 0) return -1;
        first = (unsigned)ordered[i] + 1;
    }
    return (int)syscall(SYS_close_range, first, UINT_MAX, 0);
}

static int timer_create_ms(unsigned initial, unsigned interval)
{
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (fd < 0) return -1;
    struct itimerspec timer = {
        .it_value = {(time_t)(initial / 1000), (long)(initial % 1000) * 1000000},
        .it_interval = {(time_t)(interval / 1000), (long)(interval % 1000) * 1000000}};
    if (timerfd_settime(fd, 0, &timer, NULL) < 0) { close(fd); return -1; }
    return fd;
}

static int cancellation_fd(void)
{
    sigset_t mask; sigemptyset(&mask);
    sigaddset(&mask, SIGTERM); sigaddset(&mask, SIGINT); sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return -1;
    return signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
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

static void payload(const struct config *cfg, int error_fd, int launch_gate)
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
    char permit; ssize_t received;
    do { received = read(launch_gate, &permit, 1); } while (received < 0 && errno == EINTR);
    close(launch_gate);
    if (received != 1 || permit != 'G') child_error(error_fd, 125, "cgroup", "launch gate was not released");
    if (caller_alive(cfg->caller_fd) != 1)
        child_error(error_fd, 143, "caller", "original caller exited before execution");
    int kept[CINCTA_MAX_RULES + 2] = {error_fd, cfg->notify_transport};
    size_t kept_count = 2;
    if (cfg->policy_pinned) for (size_t i = 0; i < cfg->rule_count; ++i) kept[kept_count++] = cfg->rule_fds[i];
    if (close_fds_preserve(kept, kept_count) < 0) child_error(error_fd, 125, "fd_cleanup", strerror(errno));
    if (limit_set(RLIMIT_CORE, 0) < 0 ||
        limit_set(RLIMIT_AS, (rlim_t)cfg->memory_mb * 1024 * 1024) < 0 ||
        limit_set(RLIMIT_CPU, cfg->cpu_seconds) < 0 ||
        limit_set(RLIMIT_NPROC, cfg->processes) < 0 ||
        limit_set(RLIMIT_NOFILE, cfg->nofile) < 0)
        child_error(error_fd, 125, "limits", strerror(errno));
    if (chdir(cfg->cwd) < 0) child_error(error_fd, 125, "cwd", strerror(errno));
    if (security_apply(cfg, &caps, message, sizeof(message)) < 0)
        child_error(error_fd, 125, "security", message);
    if (security_listener() >= 0) {
        if (broker_send_listener(cfg->notify_transport, security_listener()) < 0 || security_lockdown(cfg) < 0)
            child_error(error_fd, 125, "notification", strerror(errno));
        close(security_listener()); close(cfg->notify_transport);
    }
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
    char completion_error[512] = {0};
    if (cfg->audit && cfg->state && cfg->state->delivery_pending) cfg->state->audit_failed = true;
    if (cfg->resources && cfg->resources->enabled) {
        if (resource_sample(cfg->resources, completion_error, sizeof(completion_error)) < 0 ||
            (clean && resource_finish(cfg->resources, completion_error, sizeof(completion_error)) < 0)) {
            status = "setup_error"; stage = "resources"; message = completion_error; code = 125;
        }
        if (cfg->state) cfg->state->resource_removed = cfg->resources->removed;
    }
    if (cfg->workspace && cfg->state && !cfg->state->workspace_finished) {
        if (!clean) { cfg->workspace->retained = true; cfg->state->workspace_failed = true; }
        else if (workspace_finish(cfg->workspace, cfg->workspace_diff, cfg->workspace_export,
                                 cfg->workspace_keep, completion_error, sizeof(completion_error)) < 0) {
            cfg->state->workspace_failed = true; status = "setup_error"; stage = "workspace";
            message = completion_error; code = 125;
        }
        cfg->state->workspace_finished = true;
    }
    if (cfg->preparation && preparation_cleanup_container(cfg->preparation,
        cfg->workspace && (cfg->workspace->prepared || cfg->workspace->retained),
        completion_error, sizeof(completion_error)) < 0) {
        status = "setup_error"; stage = "preparation"; message = completion_error; code = 125;
    }
    if (broker_event(cfg, "finish", NULL, status, code, 0) < 0 ||
        (cfg->state && cfg->state->audit_fd >= 0 && fsync(cfg->state->audit_fd) < 0) ||
        (cfg->state && cfg->state->audit_failed)) {
        if (cfg->state) cfg->state->audit_failed = true;
        status = "setup_error"; stage = "audit"; message = "audit output failed"; code = 125;
    }
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
    struct config runtime = *cfg; cfg = &runtime;
    bool dynamic = cfg->network_allowlist || cfg->metadata || cfg->audit_syscalls;
    struct capabilities caps = {0};
    int errors[2], gate[2], transport[2] = {-1, -1};
    int listener = -1, child_pidfd = -1, deadline_fd = -1, maintenance_fd = -1;
    int broker_pidfd = -1; pid_t broker_pid = -1;
    int memory_channel[2] = {-1, -1}, validation_listener = -1;
    pid_t child;
    int preserved[CINCTA_MAX_RULES + 4] = {control, result_get_fd(), cfg->state ? cfg->state->audit_fd : -1, cfg->caller_fd};
    size_t preserved_count = 4;
    if (cfg->policy_pinned) for (size_t i = 0; i < cfg->rule_count; ++i) preserved[preserved_count++] = cfg->rule_fds[i];
    if (close_fds_preserve(preserved, preserved_count) < 0) {
        fprintf(stderr, "cincta: monitor descriptor cleanup failed\n"); return 125;
    }
    int signal_fd = cancellation_fd();
    if (signal_fd < 0) return finish(cfg, &caps, "setup_error", "signals", strerror(errno), 125, 0, false, false, true, start);
    if (caller_alive(cfg->caller_fd) != 1)
        return finish(cfg, &caps, "cancelled", "preparation", "original caller exited before execution", 143, SIGTERM, false, true, true, start);
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
    if (pipe2(gate, O_CLOEXEC) < 0)
        return finish(cfg, &caps, "setup_error", "gate", strerror(errno), 125, 0, false, false, true, start);
    runtime.notify_transport = -1;
    if (dynamic) {
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, transport) < 0)
            return finish(cfg, &caps, "setup_error", "transport", strerror(errno), 125, 0, false, false, true, start);
        int high = (int)(cfg->nofile > 1024 ? 1023 : cfg->nofile - 1);
        runtime.notify_transport = fcntl(transport[1], F_DUPFD_CLOEXEC, high);
        close(transport[1]); transport[1] = runtime.notify_transport;
        if (transport[1] < 0)
            return finish(cfg, &caps, "setup_error", "transport", strerror(errno), 125, 0, false, false, true, start);
    }
    child = fork();
    if (child < 0) {
        close(errors[0]); close(errors[1]);
        return finish(cfg, &caps, "setup_error", "fork", strerror(errno), 125, 0, false, false, true, start);
    }
    if (child == 0) payload(cfg, errors[1], gate[0]);
    close(gate[0]); close(errors[1]);
    if (transport[1] >= 0) close(transport[1]);
    char run_error[512] = {0};
    bool setup_failed = false, cpu_exhausted = false, broker_failed = false;
    if (resource_attach(cfg->resources, child, run_error, sizeof(run_error)) < 0) setup_failed = true;
    child_pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    if (child_pidfd < 0) { setup_failed = true; snprintf(run_error, sizeof(run_error), "payload pidfd: %s", strerror(errno)); }
    if (cfg->timeout_ms) {
        uint64_t spent = now_ms() - start;
        deadline_fd = timer_create_ms(spent >= cfg->timeout_ms ? 1 : cfg->timeout_ms - (unsigned)spent, 0);
        if (deadline_fd < 0) { setup_failed = true; snprintf(run_error, sizeof(run_error), "wall timer: %s", strerror(errno)); }
    }
    if (cfg->network || (cfg->resources && cfg->resources->enabled) || cfg->audit) {
        maintenance_fd = timer_create_ms(50, 50);
        if (maintenance_fd < 0) { setup_failed = true; snprintf(run_error, sizeof(run_error), "maintenance timer: %s", strerror(errno)); }
    }
    bool caller_cancelled = caller_alive(cfg->caller_fd) != 1;
    if (!setup_failed && !caller_cancelled) {
        char permit = 'G';
        if (write(gate[1], &permit, 1) != 1) setup_failed = true;
    }
    close(gate[1]);
    if (setup_failed || caller_cancelled) kill(child, SIGKILL);
    /* Parent and child both set the same group, closing the launch race. */
    int pgerr = setpgid(child, child);
    if (pgerr < 0 && errno != EACCES && errno != ESRCH) {
        kill(child, SIGKILL);
    }
    bool timed_out = false, cancelled = caller_cancelled;
    int cancel_signal = caller_cancelled ? SIGTERM : 0;
    for (;;) {
        if (cancelled || caller_alive(cfg->caller_fd) != 1) { cancelled = true; cancel_signal = SIGTERM; break; }
        siginfo_t info = {0};
        int observed = waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT);
        if (observed == 0 && info.si_pid) break;
        if (observed < 0 && errno != EINTR) { broker_failed = true; break; }
        if (setup_failed) break;
        if (caught) { cancelled = true; cancel_signal = caught; break; }
        if (cfg->state && cfg->state->audit_failed) { broker_failed = true; break; }
        struct pollfd p[] = {
            {.fd = control, .events = POLLIN | POLLHUP},
            {.fd = child_pidfd, .events = POLLIN},
            {.fd = deadline_fd, .events = POLLIN},
            {.fd = listener == -1 ? transport[0] : -1, .events = POLLIN},
            {.fd = maintenance_fd, .events = POLLIN},
            {.fd = signal_fd, .events = POLLIN},
            {.fd = broker_pidfd, .events = POLLIN},
            {.fd = memory_channel[0], .events = POLLIN},
            {.fd = cfg->caller_fd, .events = POLLIN}};
        int ready = poll(p, sizeof(p)/sizeof(p[0]), -1);
        if (ready < 0) { if (errno == EINTR) continue; broker_failed = true; break; }
        if (p[8].revents) { cancelled = true; cancel_signal = SIGTERM; break; }
        if (p[0].revents) {
            unsigned char sig; ssize_t n = read(control, &sig, 1);
            if (n == 0 || n == 1) { cancelled = true; cancel_signal = n == 1 ? sig : SIGTERM; break; }
            if (n < 0 && errno != EINTR) { broker_failed = true; break; }
        }
        if (p[1].revents & POLLIN) continue;
        if (p[5].revents & POLLIN) {
            struct signalfd_siginfo info; ssize_t n = read(signal_fd, &info, sizeof(info));
            if (n == sizeof(info)) { cancelled = true; cancel_signal = (int)info.ssi_signo; break; }
        }
        if (p[6].revents) { broker_failed = true; break; }
        if (p[7].revents & POLLIN) {
            if (broker_service_memory(memory_channel[0], validation_listener) < 0) { broker_failed = true; break; }
        }
        if (p[2].revents & POLLIN) { timed_out = true; break; }
        if (p[3].revents) {
            if (listener == -1) {
                int received = broker_receive_listener(transport[0]);
                if (received >= 0) {
                    listener = received; close(transport[0]); transport[0] = -1;
                    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, memory_channel) < 0) { broker_failed = true; break; }
                    broker_pid = fork();
                    if (broker_pid == 0) {
                        close(memory_channel[0]);
                        _exit(broker_run(cfg, listener, caps.landlock_abi, child, memory_channel[1]));
                    }
                    if (broker_pid < 0) { broker_failed = true; break; }
                    broker_pidfd = (int)syscall(SYS_pidfd_open, broker_pid, 0);
                    close(memory_channel[1]); memory_channel[1] = -1;
                    validation_listener = listener; listener = -2;
                    if (broker_pidfd < 0) { broker_failed = true; break; }
                } else if (received != -2) { broker_failed = true; break; }
            }
        }
        if (p[4].revents & POLLIN) {
            uint64_t ticks; ssize_t n = read(maintenance_fd, &ticks, sizeof(ticks));
            if (n < 0 && errno != EAGAIN && errno != EINTR) { broker_failed = true; break; }
            if (resource_sample(cfg->resources, run_error, sizeof(run_error)) < 0) { broker_failed = true; break; }
            if (resource_budget_exceeded(cfg->resources, cfg)) { cpu_exhausted = true; break; }
        }
    }
    /* Cancel is immediate SIGKILL: no grace interval in which children can
     * continue mutating files or forking. Also kill background jobs on exit. */
    resource_kill(cfg->resources, run_error, sizeof(run_error));
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    /* Only trusted worker bookkeeping remains after terminating user tasks.
     * Allow a bounded window for post-ADDFD delivery records, then force cleanup. */
    if (cfg->audit && cfg->state) {
        uint64_t settle = now_ms();
        while (cfg->state->delivery_pending && now_ms() - settle < 50) {
            struct timespec pause = {0, 1000000}; nanosleep(&pause, NULL);
        }
    }
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
    if (listener >= 0) close(listener);
    if (transport[0] >= 0) close(transport[0]);
    if (child_pidfd >= 0) close(child_pidfd);
    if (deadline_fd >= 0) close(deadline_fd);
    if (maintenance_fd >= 0) close(maintenance_fd);
    if (broker_pidfd >= 0) close(broker_pidfd);
    if (memory_channel[0] >= 0) close(memory_channel[0]);
    if (memory_channel[1] >= 0) close(memory_channel[1]);
    if (validation_listener >= 0) close(validation_listener);
    close(signal_fd);
    if (cfg->caller_fd >= 0) close(cfg->caller_fd);
    if (m.code && !strcmp(m.stage, "caller")) { cancelled = true; cancel_signal = SIGTERM; m.code = 0; }
    if (cfg->audit && cfg->state && cfg->state->delivery_pending) cfg->state->audit_failed = true;
    if (cfg->state) { cfg->state->dynamic_active = active && dynamic; cfg->state->protections_active = active; }
    result_set_phases(ready_ms - start, cleanup_start - ready_ms, now_ms() - cleanup_start);
    if (setup_failed) return finish(cfg, &caps, "setup_error", "resources", run_error, 125, 0, false, false, clean, start);
    if (broker_failed) return finish(cfg, &caps, "setup_error", "broker", "notification/audit/maintenance failed", 125, 0, false, false, clean, start);
    if (cpu_exhausted) {
        if (cfg->state) cfg->state->resource_cpu_exhausted = true;
        return finish(cfg, &caps, "resource_limit", active ? "running" : "setup", "aggregate CPU budget exhausted", 137, SIGKILL, false, false, clean, start);
    }
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
    /* Use the identity pinned before DNS/copying; reparenting must never
     * redefine the caller. A private duplicate is owned by this function. */
    int caller_fd = cfg->caller_fd >= 0 ? fcntl(cfg->caller_fd, F_DUPFD_CLOEXEC, 3) : -1;
    if (cfg->caller_fd >= 0 && caller_fd < 0) { perror("cincta: caller pidfd"); return 125; }
    if (caller_alive(caller_fd) != 1) {
        if (caller_fd >= 0) close(caller_fd);
        struct capabilities caps = {0};
        return finish(cfg, &caps, "cancelled", "preparation", "original caller exited during preparation",
                      143, SIGTERM, false, true, true, now_ms());
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0 || signal_children(false) < 0) {
        close(caller_fd); perror("cincta: recovery setup"); return 125;
    }
    int caller_signals = cancellation_fd();
    if (caller_signals < 0) { close(caller_fd); return 125; }
    if (result_open(cfg) < 0) {
        close(caller_fd); fprintf(stderr, "cincta: cannot create result: %s\n", strerror(errno)); return 125;
    }
    if (pipe2(control, O_CLOEXEC) < 0) { close(caller_fd); perror("cincta: pipe"); return 125; }
    pid_t monitor = fork();
    if (monitor < 0) { close(caller_fd); close(control[0]); close(control[1]); perror("cincta: fork"); return 125; }
    if (monitor == 0) {
        close(control[1]);
        /* The guardian must observe EOF if CLI dies before D handover. This
         * child must never retain the guardian control-pipe write end. */
        if (cfg->preparation && cfg->preparation->control_fd >= 0) close(cfg->preparation->control_fd);
        char permit; ssize_t n = 0;
        struct pollfd launch[] = {{.fd = control[0], .events = POLLIN | POLLHUP},
                                  {.fd = cfg->caller_fd, .events = POLLIN}};
        int ready;
        do { ready = poll(launch, 2, -1); } while (ready < 0 && errno == EINTR);
        if (ready > 0 && !launch[1].revents && caller_alive(cfg->caller_fd) == 1)
            do { n = read(control[0], &permit, 1); } while (n < 0 && errno == EINTR);
        if (n != 1 || permit != 'G') {
            if (cfg->preparation && cfg->preparation->status_fd >= 0) {
                char reply[1024];
                for (;;) {
                    ssize_t got = read(cfg->preparation->status_fd, reply, sizeof(reply));
                    if (got == 0) break;
                    if (got < 0 && errno == EINTR) continue;
                    if (got < 0 && errno == EAGAIN) {
                        struct pollfd p = {.fd = cfg->preparation->status_fd, .events = POLLIN | POLLHUP};
                        if (poll(&p, 1, -1) < 0 && errno != EINTR) break;
                    } else if (got < 0) break;
                }
            }
            char error[512] = {0};
            if (cfg->workspace && cfg->workspace->prepared) workspace_discard(cfg->workspace, error, sizeof(error));
            if (cfg->state) cfg->state->workspace_finished = true;
            struct capabilities caps = {0};
            _exit(finish(cfg, &caps, "cancelled", "preparation", "caller exited before monitor handover",
                143, SIGTERM, false, true, true, now_ms()));
        }
        _exit(monitor_run(cfg, control[0]));
    }
    close(control[0]);
    bool handover_failed = false, caller_cancelled = false;
    char handover_error[512] = {0};
    if (cfg->preparation && preparation_handover(cfg->preparation, monitor, handover_error, sizeof(handover_error)) < 0) {
        fprintf(stderr, "cincta: preparation handover: %s\n", handover_error);
        handover_failed = true;
        if (cfg->preparation->control_fd >= 0) { close(cfg->preparation->control_fd); cfg->preparation->control_fd = -1; }
    }
    if (caller_alive(caller_fd) != 1) { handover_failed = true; caller_cancelled = true; }
    if (!handover_failed) {
        char permit = 'G';
        if (write(control[1], &permit, 1) != 1) handover_failed = true;
    }
    if (handover_failed) { close(control[1]); control[1] = -1; }
    int monitor_fd = (int)syscall(SYS_pidfd_open, monitor, 0);
    if (monitor_fd < 0) { close(control[1]); kill(monitor, SIGKILL); }
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
        struct pollfd p[] = {{.fd = caller_fd, .events = POLLIN}, {.fd = monitor_fd, .events = POLLIN},
            {.fd = caller_signals, .events = POLLIN}};
        if (caught) continue;
        int events = poll(p, 3, monitor_fd < 0 ? 10 : -1);
        if (events > 0 && p[2].revents) {
            struct signalfd_siginfo info; ssize_t n = read(caller_signals, &info, sizeof(info));
            if (n == sizeof(info)) caught = (sig_atomic_t)info.ssi_signo;
        }
        if (events > 0 && p[0].revents) {
            caught = SIGTERM; close(caller_fd); caller_fd = -1;
        }
    }
    close(control[1]);
    if (monitor_fd >= 0) close(monitor_fd);
    close(caller_signals);
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
    return (!handover_failed || caller_cancelled) && WIFEXITED(status) ? WEXITSTATUS(status) : 125;
}
