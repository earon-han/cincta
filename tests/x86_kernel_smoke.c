#define _GNU_SOURCE
/* Actual x86_64 Linux kernel acceptance in a full-system QEMU VM. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned passes, failures, blocked, index_value;
static bool compat;
static int stream_capture = -1;

static unsigned long long milliseconds(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000 + (unsigned long long)t.tv_nsec / 1000000;
}

static void record(const char *name, const char *outcome, int expected, int observed, const char *detail)
{
    if (!strcmp(outcome, "PASS")) ++passes;
    else if (!strcmp(outcome, "FAIL")) ++failures;
    else ++blocked;
    printf("CINCTA_X86_CASE {\"name\":\"%s\",\"outcome\":\"%s\",\"expected\":%d,\"observed\":%d,\"detail\":\"%s\"}\n",
           name, outcome, expected, observed, detail);
    fflush(stdout);
}

static int file_read(const char *path, char *buffer, size_t size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buffer, size - 1); close(fd);
    if (n < 0) return -1;
    buffer[n] = 0; return (int)n;
}

static pid_t published_pid(const char *path, unsigned timeout_ms)
{
    unsigned long long start = milliseconds();
    do {
        char text[64], *end = NULL;
        int length = file_read(path, text, sizeof(text));
        if (length > 0 && text[length - 1] == '\n') {
            errno = 0; long value = strtol(text, &end, 10);
            if (!errno && value > 0 && value <= 2147483647 && end && !strcmp(end, "\n")) return (pid_t)value;
        }
        usleep(1000);
    } while (milliseconds() - start < timeout_ms);
    return -1;
}

static void publication_fixture_test(void)
{
    const char *path = "/tmp/x86-results/delayed-pid";
    pid_t writer = fork();
    if (writer == 0) {
        int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd < 0) _exit(1);
        /* File existence is deliberately visible before the complete PID. */
        usleep(20000);
        ssize_t n = write(fd, "1234\n", 5); close(fd); _exit(n == 5 ? 0 : 1);
    }
    pid_t value = published_pid(path, 1000);
    int status; if (writer > 0) waitpid(writer, &status, 0);
    record("fixture.complete-pid-publication", value == 1234 ? "PASS" : "FAIL", 1234, value,
           "wait for full positive PID instead of file existence");
}

static int await_child(pid_t pid, unsigned timeout_ms)
{
    int status;
    unsigned long long start = milliseconds();
    for (;;) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        if (got < 0 && errno != EINTR) return 125;
        if (milliseconds() - start > timeout_ms) { kill(pid, SIGKILL); waitpid(pid, &status, 0); return 250; }
        usleep(1000);
    }
}

static pid_t spawn(char *const *args, const char *output)
{
    pid_t child = fork();
    if (child != 0) return child;
    int fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); if (fd > 2) close(fd); }
    execv(args[0], args); _exit(125);
}

static pid_t spawn_stream(char *const *args)
{
    int pair[2];
    if (pipe(pair) < 0) return -1;
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]); dup2(pair[1], STDOUT_FILENO); dup2(pair[1], STDERR_FILENO);
        if (pair[1] > 2) close(pair[1]);
        execv(args[0], args); _exit(125);
    }
    close(pair[1]); stream_capture = pair[0]; return child;
}

static void finish_stream(const char *output)
{
    if (stream_capture < 0) return;
    int fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    char bytes[4096]; ssize_t n;
    while ((n = read(stream_capture, bytes, sizeof(bytes))) > 0) {
        if (fd >= 0 && write(fd, bytes, (size_t)n) != n) break;
    }
    if (fd >= 0) close(fd);
    close(stream_capture); stream_capture = -1;
}

static int run_case(const char *name, const char *const *options, const char *const *command,
                    int expected, const char *expected_status)
{
    char result[160], output[160];
    snprintf(result, sizeof(result), "/tmp/x86-results/%u.json", ++index_value);
    snprintf(output, sizeof(output), "/tmp/x86-results/%u.out", index_value);
    char *args[100]; unsigned n = 0;
    args[n++] = "/cincta"; args[n++] = "run";
    if (compat) args[n++] = "--compat";
    args[n++] = "--rx"; args[n++] = "/adversary";
    args[n++] = "--rx"; args[n++] = "/x86-smoke";
    bool workspace = false;
    for (unsigned i = 0; options && options[i]; ++i) if (!strcmp(options[i], "--workspace")) workspace = true;
    if (!workspace) { args[n++] = "--cwd"; args[n++] = "/tmp"; }
    args[n++] = "--result"; args[n++] = result;
    args[n++] = "--timeout-ms"; args[n++] = "10000";
    for (unsigned i = 0; options && options[i]; ++i) args[n++] = (char *)options[i];
    args[n++] = "--";
    for (unsigned i = 0; command[i]; ++i) args[n++] = (char *)command[i];
    args[n] = NULL;
    pid_t child = workspace ? spawn_stream(args) : spawn(args, output);
    int code = child > 0 ? await_child(child, 15000) : 125;
    if (workspace) finish_stream(output);
    char report[16384], out[2048];
    bool clean = file_read(result, report, sizeof(report)) >= 0 && strstr(report, "\"cleanup_complete\":true");
    char wanted[100]; snprintf(wanted, sizeof(wanted), "\"status\":\"%s\"", expected_status);
    bool status_ok = clean && strstr(report, wanted);
    bool pass = code == expected && status_ok;
    record(name, pass ? "PASS" : "FAIL", expected, code, pass ? "kernel enforcement and cleanup confirmed" : "inspect serial evidence");
    if (!pass) {
        if (clean) printf("CINCTA_X86_FAILURE_RESULT %s\n", report);
        if (file_read(output, out, sizeof(out)) >= 0) printf("CINCTA_X86_FAILURE_OUTPUT %s\n", out);
    }
    return pass ? 0 : -1;
}

static int client(bool udp, unsigned port)
{
    int fd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0) return errno;
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);
    struct timeval deadline = {.tv_sec = 3};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) < 0) return errno;
    if (udp) {
        if (sendto(fd, "hello", 5, 0, (struct sockaddr *)&peer, sizeof(peer)) != 5) return errno;
    } else if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0 || write(fd, "hello", 5) != 5) return errno;
    char bytes[8]; ssize_t n = read(fd, bytes, sizeof(bytes));
    close(fd);
    return n == 5 && !memcmp(bytes, "hello", 5) ? 0 : 99;
}

static void network_case(bool udp)
{
    int fd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(local);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0 || getsockname(fd, (struct sockaddr *)&local, &size) < 0 ||
        (!udp && listen(fd, 1) < 0)) { record(udp ? "network.udp-broker" : "network.tcp-broker", "FAIL", 0, errno, "local server setup"); return; }
    pid_t server = fork();
    if (server == 0) {
        alarm(8); char bytes[32];
        if (udp) {
            struct sockaddr_in peer; socklen_t peer_size = sizeof(peer);
            ssize_t n = recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr *)&peer, &peer_size);
            if (n > 0 && sendto(fd, bytes, (size_t)n, 0, (struct sockaddr *)&peer, peer_size) == n) _exit(0);
        } else {
            int stream = accept(fd, NULL, NULL);
            if (stream >= 0) { ssize_t n = read(stream, bytes, sizeof(bytes)); if (n > 0 && write(stream, bytes, (size_t)n) == n) _exit(0); }
        }
        _exit(1);
    }
    close(fd);
    char rule[100], port[20];
    snprintf(port, sizeof(port), "%u", ntohs(local.sin_port));
    snprintf(rule, sizeof(rule), "%s:127.0.0.1:%s", udp ? "udp" : "tcp", port);
    const char *options[] = {"--network", "allowlist", "--allow-net", rule, NULL};
    const char *command[] = {"/x86-smoke", udp ? "udp-client" : "tcp-client", port, NULL};
    run_case(udp ? "network.udp-broker" : "network.tcp-broker", options, command, 0, "ok");
    int status = await_child(server, 1000);
    if (status != 0) record("network.echo-server", "FAIL", 0, status, "server did not receive the expected bytes");
}

static void lifecycle_signal(bool kill_cli, bool kill_monitor)
{
    const char *name = kill_cli ? "lifecycle.cli-sigkill" : kill_monitor ? "lifecycle.monitor-sigkill" : "lifecycle.cancel";
    char marker[100], result[100], output[100];
    snprintf(marker, sizeof(marker), "/fixtures/write/pid-%u", ++index_value);
    snprintf(result, sizeof(result), "/tmp/x86-results/signal-%u.json", index_value);
    snprintf(output, sizeof(output), "/tmp/x86-results/signal-%u.out", index_value);
    char *args[32]; unsigned n = 0;
    args[n++] = "/cincta"; args[n++] = "run";
    if (compat) args[n++] = "--compat";
    args[n++] = "--rx"; args[n++] = "/adversary";
    args[n++] = "--rw"; args[n++] = "/fixtures/write";
    args[n++] = "--cwd"; args[n++] = "/tmp";
    args[n++] = "--result"; args[n++] = result;
    args[n++] = "--"; args[n++] = "/adversary"; args[n++] = "tree"; args[n++] = marker; args[n] = NULL;
    pid_t cli = spawn(args, output); char text[16384];
    pid_t descendant = published_pid(marker, 5000);
    unsigned long long start;
    pid_t victim = cli;
    if (kill_monitor) {
        char path[100]; snprintf(path, sizeof(path), "/proc/%ld/task/%ld/children", (long)cli, (long)cli);
        victim = file_read(path, text, sizeof(text)) >= 0 ? (pid_t)atoi(text) : -1;
    }
    if (victim > 0) kill(victim, kill_cli || kill_monitor ? SIGKILL : SIGTERM);
    int code = cli > 0 ? await_child(cli, 8000) : 125;
    start = milliseconds(); bool gone = false, report_ready = false;
    while (milliseconds() - start < 4000) {
        int st; while (waitpid(-1, &st, WNOHANG | __WALL) > 0) { }
        char proc[80]; snprintf(proc, sizeof(proc), "/proc/%ld", (long)descendant);
        gone = descendant > 0 && access(proc, F_OK) < 0 && errno == ENOENT;
        report_ready = file_read(result, text, sizeof(text)) >= 0 && strstr(text, "\"cleanup_complete\":true");
        if (gone && report_ready) break;
        usleep(1000);
    }
    int expected = kill_cli ? 137 : kill_monitor ? 125 : 143;
    record(name, gone && report_ready && code == expected ? "PASS" : "FAIL", expected, code,
           gone && report_ready ? "descendant reaped and completion JSON observed" : "cleanup not confirmed");
    if (!gone || !report_ready || code != expected) {
        printf("CINCTA_X86_FAILURE_LIFECYCLE cli=%ld victim=%ld descendant=%ld gone=%d report_ready=%d\n",
               (long)cli, (long)victim, (long)descendant, gone, report_ready);
        if (file_read(result, text, sizeof(text)) >= 0) printf("CINCTA_X86_FAILURE_RESULT %s\n", text);
        if (file_read(output, text, sizeof(text)) >= 0) printf("CINCTA_X86_FAILURE_OUTPUT %s\n", text);
        char proc[100]; snprintf(proc, sizeof(proc), "/proc/%ld/stat", (long)descendant);
        if (file_read(proc, text, sizeof(text)) >= 0) printf("CINCTA_X86_FAILURE_PROC %s\n", text);
    }
}

int main(int argc, char **argv)
{
    if (argc == 3 && (!strcmp(argv[1], "tcp-client") || !strcmp(argv[1], "udp-client")))
        return client(!strcmp(argv[1], "udp-client"), (unsigned)atoi(argv[2]));
    if (getuid() != 501) { fprintf(stderr, "smoke requires unprivileged uid 501\n"); return 125; }
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    mkdir("/tmp/x86-results", 0700);
    char probe[4096];
    char *probe_args[] = {"/cincta", "probe", NULL};
    pid_t pid = spawn(probe_args, "/tmp/x86-results/probe.json");
    int code = pid > 0 ? await_child(pid, 10000) : 125;
    bool probed = file_read("/tmp/x86-results/probe.json", probe, sizeof(probe)) >= 0;
    printf("CINCTA_X86_PROBE %s\n", probed ? probe : "{}");
    bool strict = probed && strstr(probe, "\"strict_supported\":true");
    bool supported = strict || (probed && strstr(probe, "\"compat_supported\":true"));
    compat = !strict;
    record("probe.kernel-landlock-seccomp", code == 0 && supported ? "PASS" : "BLOCKED", 0, code,
           strict ? "strict Landlock plus seccomp available" : supported ? "compat Landlock plus seccomp available" : "required primitive absent");
    if (!supported) goto done;
    publication_fixture_test();
    const char *read_secret[] = {"/adversary", "read", "/fixtures/secret", NULL};
    const char *read_allowed[] = {"/adversary", "read", "/fixtures/readable", NULL};
    const char *write_allowed[] = {"/adversary", "write", "/fixtures/write/created", NULL};
    const char *read_opt[] = {"--ro", "/fixtures/readable", NULL};
    const char *write_opt[] = {"--rw", "/fixtures/write", NULL};
    run_case("filesystem.default-deny", NULL, read_secret, EACCES, "exit");
    run_case("filesystem.read-allowed", read_opt, read_allowed, 0, "ok");
    run_case("filesystem.write-allowed", write_opt, write_allowed, 0, "ok");
    const char *ro_write[] = {"/adversary", "write", "/fixtures/readable", NULL};
    run_case("filesystem.read-only", read_opt, ro_write, EACCES, "exit");
    const char *operations[] = {"get-nnp", "socket", "ptrace", "bpf", "unshare", "setsid", "setpgid", "clone-ns", "clone-parent", "io-uring", "clone3", "x32", "i386-entry"};
    for (unsigned i = 0; i < sizeof(operations)/sizeof(operations[0]); ++i) {
        const char *command[] = {"/adversary", operations[i], "inet", NULL};
        char name[120]; snprintf(name, sizeof(name), "seccomp.%s", operations[i]);
        int expected = !strcmp(operations[i], "get-nnp") ? 0 : !strcmp(operations[i], "clone3") ? ENOSYS :
                       (!strcmp(operations[i], "x32") || !strcmp(operations[i], "i386-entry")) ? 128 + SIGSYS : EPERM;
        run_case(name, NULL, command, expected, expected == 0 ? "ok" : expected == 128 + SIGSYS ? "signal" : "exit");
    }
    const char *chmod_command[] = {"/adversary", "chmod", "/fixtures/write/created", NULL};
    run_case("metadata.default-deny", write_opt, chmod_command, EPERM, "exit");
    const char *metadata_options[] = {"--metadata", "--rw", "/fixtures/write", NULL};
    run_case("metadata.fixed-object-chmod", metadata_options, chmod_command, 0, "ok");
    const char *audit_options[] = {"--audit", "/tmp/x86-results/audit.jsonl", "--audit-syscalls",
        "--ro", "/fixtures/readable", NULL};
    run_case("audit.actual-file-open", audit_options, read_allowed, 0, "ok");
    const char *audit_quota_options[] = {"--audit", "/tmp/x86-results/audit-quota.jsonl", "--audit-max-bytes", "100", NULL};
    run_case("audit.quota-fails-closed", audit_quota_options, read_allowed, 125, "setup_error");
    const char *workspace_options[] = {"--workspace", "/fixtures/workspace-source",
        "--workspace-diff", "/tmp/x86-results/workspace-diff.json",
        "--workspace-export", "/tmp/x86-results/workspace-export", NULL};
    const char *workspace_command[] = {"/adversary", "write", "generated", NULL};
    run_case("workspace.snapshot-export", workspace_options, workspace_command, 0, "ok");
    char original[100];
    bool source_ok = file_read("/fixtures/workspace-source/original", original, sizeof(original)) >= 0 &&
        !strcmp(original, "source-must-stay-unchanged\n") && access("/fixtures/workspace-source/generated", F_OK) < 0 &&
        access("/tmp/x86-results/workspace-export/generated", F_OK) == 0;
    record("workspace.original-unchanged", source_ok ? "PASS" : "FAIL", 0, source_ok ? 0 : 1,
           "source remains original and generated file exists only in export");
    if (access("/sys/fs/cgroup/cincta-x86/cgroup.controllers", R_OK) == 0) {
        const char *resource_options[] = {"--cgroup-parent", "/sys/fs/cgroup/cincta-x86",
            "--tree-memory-mb", "64", "--tree-pids", "32", "--tree-cpu-percent", "50", NULL};
        const char *nnp_command[] = {"/adversary", "get-nnp", NULL};
        run_case("resources.delegated-tree", resource_options, nnp_command, 0, "ok");
        const char *cpu_options[] = {"--cgroup-parent", "/sys/fs/cgroup/cincta-x86", "--tree-cpu-ms", "120", NULL};
        const char *cpu_command[] = {"/adversary", "cpu", NULL};
        run_case("resources.aggregate-cpu-budget", cpu_options, cpu_command, 137, "resource_limit");
    } else record("resources.delegated-tree", "BLOCKED", 0, 0, "guest cgroup controllers unavailable");
    network_case(false); network_case(true);
    const char *timeout_options[] = {"--rw", "/fixtures/write", "--timeout-ms", "500", NULL};
    const char *tree_command[] = {"/adversary", "tree", "/fixtures/write/timeout-pid", NULL};
    run_case("lifecycle.timeout", timeout_options, tree_command, 124, "timeout");
    pid_t expired = published_pid("/fixtures/write/timeout-pid", 1000);
    char expired_path[80]; snprintf(expired_path, sizeof(expired_path), "/proc/%ld", (long)expired);
    bool expired_gone = expired > 0 && access(expired_path, F_OK) < 0 && errno == ENOENT;
    record("lifecycle.timeout-descendant-reaped", expired_gone ? "PASS" : "FAIL", 0,
           expired_gone ? 0 : 1, "independent procfs absence after timeout");
    lifecycle_signal(false, false); lifecycle_signal(true, false); lifecycle_signal(false, true);
done:
    printf("CINCTA_X86_SUMMARY {\"PASS\":%u,\"FAIL\":%u,\"BLOCKED\":%u,\"uid\":%lu,\"mode\":\"%s\"}\n",
           passes, failures, blocked, (unsigned long)getuid(), compat ? "compat" : "strict");
    return failures ? 1 : blocked ? 2 : 0;
}
