#define _GNU_SOURCE
#include "cincta.h"
#include "broker.h"
#include "network.h"
#include "resources.h"
#include "workspace.h"
#include "preparation.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <linux/magic.h>
#include <linux/stat.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *out)
{
    fprintf(out,
        "cincta " CINCTA_VERSION " (Linux x86_64/aarch64)\n"
        "Usage: cincta probe\n"
        "       cincta run [OPTIONS] -- COMMAND [ARGS...]\n"
        "  --ro PATH / --rw PATH / --rx PATH   Explicit absolute path grants\n"
        "  --cwd PATH                         Working directory\n"
        "  --network none|host                Default: none (all sockets denied)\n"
        "  --compat                           Explicit ABI 3-5 IPC scope downgrade\n"
        "  --timeout-ms N                     Wall time (default 30000; 0 unlimited)\n"
        "  --memory-mb N                      RLIMIT_AS (default 512)\n"
        "  --cpu-seconds N                    RLIMIT_CPU (default 30)\n"
        "  --processes N                      Per-UID RLIMIT_NPROC (default 256)\n"
        "  --nofile N                         RLIMIT_NOFILE (default 128)\n"
        "  --env KEY=VALUE                    Add environment variable\n"
        "  --result PATH                      Exclusive new JSON result file\n"
        "  --network allowlist --allow-net tcp:HOST/CIDR:PORT[-PORT]\n"
        "  --allow-net udp:HOST/CIDR:PORT      Repeatable; IPv6 in [brackets]\n"
        "  --metadata                         Broker safe rw metadata operations\n"
        "  --audit PATH [--audit-syscalls]     Exclusive JSONL events/requests\n"
        "  --audit-max-bytes N                Audit cap (default 67108864)\n"
        "  --audit-max-records N              Audit record cap (default 1000000)\n"
        "  --cgroup-parent PATH               Explicit delegated cgroup v2 root\n"
        "  --tree-memory-mb N --tree-pids N --tree-cpu-percent N --tree-cpu-ms N\n"
        "  --workspace SOURCE                 Isolated physical workspace snapshot\n"
        "  --workspace-parent DIR --workspace-diff PATH --workspace-export DIR\n"
        "  --workspace-keep --workspace-max-files N --workspace-max-bytes N\n"
        "  --workspace-exec                   Explicitly execute snapshot files\n"
        "No implicit filesystem grants. Environment starts with PATH and LANG.\n"
        "Strict mode requires Landlock ABI 6; compat still requires ABI 3 + BPF.\n");
}

static int bad(const char *message, const char *arg)
{
    fprintf(stderr, "cincta: %s: %s\n", message, arg);
    return 125;
}

static bool number(const char *s, unsigned *value)
{
    char *end = NULL;
    unsigned long n;
    if (!*s || *s < '0' || *s > '9') return false;
    errno = 0;
    n = strtoul(s, &end, 10);
    if (errno || *end || n > UINT_MAX) return false;
    *value = (unsigned)n;
    return true;
}

static bool env_valid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || *p == '_')) return false;
    for (++p; *p && *p != '='; ++p)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || *p == '_')) return false;
    return *p == '=';
}

static bool beneath(const char *parent, const char *child)
{
    size_t n = strlen(parent);
    return !strncmp(parent, child, n) && (n == 1 || child[n] == '/' || !child[n]);
}

static uint64_t milliseconds(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

static int normalize_stdio(void)
{
    for (int fd = 0; fd < 3; ++fd) if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
        int replacement = open("/dev/null", fd ? O_WRONLY : O_RDONLY);
        if (replacement != fd) { if (replacement >= 0) close(replacement); return -1; }
    }
    return 0;
}

/* Canonical namespace paths can name the same filesystem subtree through
 * different bind mounts, including a bind rooted below an authorized root.
 * A pinned FD's mount ID selects the exact mountinfo record (not an ambiguous
 * longest pathname prefix). Host mount/rename changes during preparation are
 * outside the required stable, trusted namespace contract. */
struct filesystem_path { dev_t device; char path[PATH_MAX * 2]; };

static int mount_field(const char *field, char out[PATH_MAX])
{
    size_t used = 0, size = strlen(field);
    for (size_t j = 0; j < size; ++j) {
        if (used + 1 >= PATH_MAX) { errno = ENAMETOOLONG; return -1; }
        if (field[j] == '\\' && size - j >= 4 &&
            field[j+1] >= '0' && field[j+1] <= '7' &&
            field[j+2] >= '0' && field[j+2] <= '7' &&
            field[j+3] >= '0' && field[j+3] <= '7') {
            unsigned char byte = (unsigned char)((field[j+1]-'0')*64 + (field[j+2]-'0')*8 + field[j+3]-'0');
            if (!byte) { errno = EPROTO; return -1; }
            out[used++] = (char)byte; j += 3;
        } else out[used++] = field[j];
    }
    out[used] = 0;
    if (out[0] != '/') { errno = EPROTO; return -1; }
    return 0;
}

static int filesystem_path(int object, const char *canonical, struct filesystem_path *out)
{
    struct stat st;
    struct statx extended = {0};
    if (fstat(object, &st) < 0 ||
        syscall(SYS_statx, object, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                STATX_MNT_ID, &extended) < 0) return -1;
    if (!(extended.stx_mask & STATX_MNT_ID)) { errno = ENOTSUP; return -1; }
    if (major(st.st_dev) != extended.stx_dev_major || minor(st.st_dev) != extended.stx_dev_minor) {
        errno = ESTALE; return -1;
    }
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f) return -1;
    char *line = NULL; size_t capacity = 0; int result = -1;
    while (getline(&line, &capacity, f) > 0) {
        char *save = NULL, *fields[5];
        fields[0] = strtok_r(line, " ", &save);
        for (int i = 1; i < 5; ++i) fields[i] = strtok_r(NULL, " ", &save);
        if (!fields[0] || !fields[4]) { errno = EPROTO; break; }
        char *end; errno = 0;
        unsigned long long id = strtoull(fields[0], &end, 10);
        if (errno || *end) { errno = EPROTO; break; }
        if (id != extended.stx_mnt_id) continue;
        unsigned device_major, device_minor; char extra;
        if (sscanf(fields[2], "%u:%u%c", &device_major, &device_minor, &extra) != 2 ||
            device_major != extended.stx_dev_major || device_minor != extended.stx_dev_minor) {
            errno = ESTALE; break;
        }
        char root[PATH_MAX], mount[PATH_MAX];
        if (mount_field(fields[3], root) < 0 || mount_field(fields[4], mount) < 0) break;
        if (!beneath(mount, canonical)) { errno = ESTALE; break; }
        const char *suffix = canonical + strlen(mount);
        while (*suffix == '/') ++suffix;
        int length = snprintf(out->path, sizeof(out->path), "%s%s%s", root,
            *suffix && strcmp(root, "/") ? "/" : "", suffix);
        if (length < 0 || (size_t)length >= sizeof(out->path)) { errno = ENAMETOOLONG; break; }
        out->device = st.st_dev; result = 0; break;
    }
    if (result < 0 && !errno) errno = ESTALE;
    int saved = errno;
    free(line); fclose(f); errno = saved;
    return result;
}

static int filesystem_path_open_flags(const char *canonical, int flags, struct filesystem_path *out)
{
    int fd = open(canonical, O_PATH | O_NOFOLLOW | O_CLOEXEC | flags);
    if (fd < 0) return -1;
    int result = filesystem_path(fd, canonical, out), saved = errno;
    close(fd); errno = saved; return result;
}

static int filesystem_path_open(const char *canonical, struct filesystem_path *out)
{
    return filesystem_path_open_flags(canonical, O_DIRECTORY, out);
}

static bool filesystem_beneath(const struct filesystem_path *root, const struct filesystem_path *candidate)
{
    return root->device == candidate->device && beneath(root->path, candidate->path);
}

static bool filesystem_overlap(const struct filesystem_path *a, const struct filesystem_path *b)
{
    return filesystem_beneath(a, b) || filesystem_beneath(b, a);
}

static int output_ancestors_safe(const struct config *cfg, const char *parent)
{
    int fd = open(parent, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct filesystem_path output, boundary;
    if (filesystem_path(fd, parent, &output) < 0) { close(fd); return -1; }
    for (size_t i = 0; i < cfg->rule_count; ++i) if (cfg->rules[i].mode == PATH_RW) {
        if (filesystem_path(cfg->rule_fds[i], cfg->rule_targets[i], &boundary) < 0 ||
            filesystem_beneath(&boundary, &output)) { close(fd); return -1; }
    }
    if (cfg->workspace &&
        (filesystem_path_open(cfg->workspace->source, &boundary) < 0 || filesystem_beneath(&boundary, &output) ||
         filesystem_path_open(cfg->workspace->root, &boundary) < 0 || filesystem_beneath(&boundary, &output))) {
        close(fd); return -1;
    }
    struct stat source = {0}, private_root = {0};
    if (cfg->workspace && (stat(cfg->workspace->source, &source) < 0 || stat(cfg->workspace->root, &private_root) < 0)) { close(fd); return -1; }
    for (int depth = 0; depth < 512; ++depth) {
        struct stat st;
        if (fstat(fd, &st) < 0) { close(fd); return -1; }
        for (size_t i = 0; i < cfg->rule_count; ++i) if (cfg->rules[i].mode == PATH_RW) {
            struct stat rule;
            if (fstat(cfg->rule_fds[i], &rule) < 0 ||
                (rule.st_dev == st.st_dev && rule.st_ino == st.st_ino)) { close(fd); return -1; }
        }
        if (cfg->workspace && ((st.st_dev == source.st_dev && st.st_ino == source.st_ino) ||
            (st.st_dev == private_root.st_dev && st.st_ino == private_root.st_ino))) { close(fd); return -1; }
        int up = openat(fd, "..", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (up < 0) { close(fd); return -1; }
        struct stat ancestor;
        if (fstat(up, &ancestor) < 0) { close(up); close(fd); return -1; }
        close(fd);
        if (ancestor.st_dev == st.st_dev && ancestor.st_ino == st.st_ino) { close(up); return 0; }
        fd = up;
    }
    close(fd); return -1;
}

static bool overlap(const char *a, const char *b) { return beneath(a, b) || beneath(b, a); }

static int mount_point(char *line, char mount[PATH_MAX])
{
    char *save = NULL, *field = strtok_r(line, " ", &save);
    for (int i = 1; field && i < 5; ++i) field = strtok_r(NULL, " ", &save);
    if (!field) return -1;
    return mount_field(field, mount);
}

/* Validate before the guardian creates anything, including bind aliases of
 * the source at a different absolute pathname. Namespace changes by other
 * trusted host processes are outside the immutable preparation assumption. */
static int workspace_layout_safe(const char *source, const char *parent)
{
    struct filesystem_path original_path, parent_path;
    if (filesystem_path_open(source, &original_path) < 0 || filesystem_path_open(parent, &parent_path) < 0 ||
        filesystem_beneath(&original_path, &parent_path)) return -1;
    struct stat original;
    if (stat(source, &original) < 0) return -1;
    int fd = open(parent, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    bool outside = false;
    for (unsigned depth = 0; depth < 512; ++depth) {
        struct stat st, ancestor;
        if (fstat(fd, &st) < 0 || (st.st_dev == original.st_dev && st.st_ino == original.st_ino)) break;
        int up = openat(fd, "..", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (up < 0) break;
        if (fstat(up, &ancestor) < 0) { close(up); break; }
        if (st.st_dev == ancestor.st_dev && st.st_ino == ancestor.st_ino) { close(up); outside = true; break; }
        close(fd); fd = up;
    }
    close(fd);
    if (!outside) return -1;
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f) return -1;
    char *line = NULL; size_t capacity = 0; int result = 0;
    while (getline(&line, &capacity, f) > 0) {
        char mount[PATH_MAX];
        if (mount_point(line, mount) < 0 || (strcmp(source, mount) && beneath(source, mount))) { result = -1; break; }
    }
    if (ferror(f)) result = -1;
    free(line); fclose(f); return result;
}

static int trusted_output(const struct config *cfg, const char *path)
{
    if (!path) return 0;
    char copy[PATH_MAX], parent[PATH_MAX], canonical[PATH_MAX];
    if (strlen(path) >= sizeof(copy)) return -1;
    strcpy(copy, path); char *slash = strrchr(copy, '/');
    if (!slash || !slash[1]) return -1;
    if (slash == copy) slash[1] = 0; else *slash = 0;
    if (!realpath(copy, parent)) return -1;
    for (size_t i = 0; i < cfg->rule_count; ++i)
        if (cfg->rules[i].mode == PATH_RW && realpath(cfg->rules[i].path, canonical) && beneath(canonical, parent)) return -1;
    if (cfg->policy_pinned && output_ancestors_safe(cfg, parent) < 0) return -1;
    return 0;
}

static int cgroup_grants_safe(const struct config *cfg)
{
    bool outputs = cfg->result || cfg->audit || cfg->workspace_diff || cfg->workspace_export;
    if (!cfg->cgroup_parent && !outputs && !cfg->workspace) return 0;
    if (cfg->cgroup_parent) for (int fd = 0; fd < 3; ++fd) {
        struct statfs fs;
        if (fstatfs(fd, &fs) == 0 && (unsigned long)fs.f_type == CGROUP2_SUPER_MAGIC &&
            (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY) return -1;
    }
    for (size_t i = 0; i < cfg->rule_count; ++i) if (cfg->rules[i].mode == PATH_RW) {
        struct statfs fs;
        if (fstatfs(cfg->rule_fds[i], &fs) < 0 || (cfg->cgroup_parent && (unsigned long)fs.f_type == CGROUP2_SUPER_MAGIC)) return -1;
    }
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f) return -1;
    char *line = NULL; size_t capacity = 0; int result = 0;
    while (getline(&line, &capacity, f) > 0) {
        bool cgroup = strstr(line, " - cgroup2 ") != NULL;
        char mount[PATH_MAX];
        if (mount_point(line, mount) < 0) { result = -1; break; }
        /* A source submount may alias an otherwise unrelated export parent.
         * Refuse these sources rather than modifying their original view. */
        if (cfg->workspace && strcmp(cfg->workspace->source, mount) &&
            beneath(cfg->workspace->source, mount)) { result = -1; break; }
        for (size_t i = 0; i < cfg->rule_count; ++i)
            if (cfg->rules[i].mode == PATH_RW && beneath(cfg->rule_targets[i], mount) &&
                ((cfg->cgroup_parent && cgroup) || (outputs && strcmp(cfg->rule_targets[i], mount)))) result = -1;
        if (result < 0) break;
    }
    if (ferror(f)) result = -1;
    free(line); fclose(f); return result;
}

int main(int argc, char **argv)
{
    /* Normalize before ANY policy/result/audit open, preventing trusted FDs
     * from occupying the intentionally inherited stdio slots. */
    if (normalize_stdio() < 0) return 125;
    struct sigaction initial = {.sa_handler = SIG_DFL};
    sigemptyset(&initial.sa_mask);
    sigaction(SIGCHLD, &initial, NULL); sigaction(SIGTERM, &initial, NULL);
    sigaction(SIGINT, &initial, NULL); sigaction(SIGHUP, &initial, NULL);
    sigset_t initial_mask; sigemptyset(&initial_mask); sigprocmask(SIG_SETMASK, &initial_mask, NULL);
    struct config cfg = { .caller_fd = -1, .timeout_ms = 30000, .memory_mb = 512,
        .cpu_seconds = 30, .processes = 256, .nofile = 128,
        .audit_max_bytes = 64 * 1024 * 1024, .audit_max_records = 1000000 };
    char cwd[PATH_MAX];
    const char *net_rules[CINCTA_NET_MAX_RULES]; size_t net_count = 0;
    const char *workspace_source = NULL, *workspace_parent = NULL;
    uint64_t workspace_files = 0, workspace_bytes = 0;
    bool cwd_explicit = false, network_explicit = false;
    struct workspace_ctx local_workspace = {0}; struct resource_ctx local_resources = {0};
    struct workspace_ctx *workspace = &local_workspace;
    struct resource_ctx *resources = &local_resources;
    struct preparation_guard guard = {.pid = -1, .control_fd = -1, .status_fd = -1};
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "help"))) {
        usage(stdout); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts(CINCTA_VERSION); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "probe")) {
        struct capabilities caps = {0};
        if (security_probe(&caps) < 0) return bad("probe failed", strerror(errno));
        printf("{\"schema_version\":1,\"landlock_abi\":%d,\"landlock_errno\":%d,"
               "\"seccomp\":%s,\"seccomp_errno\":%d,\"strict_supported\":%s,"
               "\"compat_supported\":%s}\n", caps.landlock_abi, caps.landlock_errno,
               caps.seccomp ? "true" : "false", caps.seccomp_errno,
               caps.landlock_abi >= 6 && caps.seccomp ? "true" : "false",
               caps.landlock_abi >= 3 && caps.seccomp ? "true" : "false");
        return 0;
    }
    if (argc < 4 || strcmp(argv[1], "run")) { usage(stderr); return 125; }
    if (caller_capture(&cfg.caller_fd) < 0) return bad("capture original caller", strerror(errno));
    if (!getcwd(cwd, sizeof(cwd))) return bad("getcwd failed", strerror(errno));
    cfg.cwd = cwd;
    cfg.env[cfg.env_count++] = "PATH=/usr/bin:/bin";
    cfg.env[cfg.env_count++] = "LANG=C";
    for (int i = 2; i < argc; ++i) {
        const char *opt = argv[i];
        if (!strcmp(opt, "--")) {
            if (i + 1 == argc) return bad("missing command", opt);
            cfg.command = &argv[i + 1]; break;
        }
        if (!strcmp(opt, "--compat")) { cfg.compat = true; continue; }
        if (!strcmp(opt, "--metadata")) { cfg.metadata = true; continue; }
        if (!strcmp(opt, "--audit-syscalls")) { cfg.audit_syscalls = true; continue; }
        if (!strcmp(opt, "--workspace-keep")) { cfg.workspace_keep = true; continue; }
        if (!strcmp(opt, "--workspace-exec")) { cfg.workspace_exec = true; continue; }
        if (i + 1 >= argc) return bad("missing option value", opt);
        const char *val = argv[++i];
        if (!strcmp(opt, "--ro") || !strcmp(opt, "--rw") || !strcmp(opt, "--rx")) {
            if (*val != '/') return bad("path must be absolute", val);
            if (cfg.rule_count == CINCTA_MAX_RULES) return bad("too many path rules", opt);
            cfg.rules[cfg.rule_count++] = (struct path_rule){val,
                !strcmp(opt, "--ro") ? PATH_RO : !strcmp(opt, "--rw") ? PATH_RW : PATH_RX};
        } else if (!strcmp(opt, "--cwd")) {
            if (*val != '/') return bad("cwd must be absolute", val);
            cfg.cwd = val;
            cwd_explicit = true;
        } else if (!strcmp(opt, "--result")) {
            if (cfg.result) return bad("duplicate result option", opt);
            if (*val != '/') return bad("result path must be absolute", val);
            cfg.result = val;
        } else if (!strcmp(opt, "--network")) {
            if (strcmp(val, "none") && strcmp(val, "host") && strcmp(val, "allowlist")) return bad("invalid network mode", val);
            cfg.network_host = !strcmp(val, "host");
            cfg.network_allowlist = !strcmp(val, "allowlist"); network_explicit = true;
        } else if (!strcmp(opt, "--allow-net")) {
            if (net_count == CINCTA_NET_MAX_RULES) return bad("too many network rules", opt);
            net_rules[net_count++] = val;
        } else if (!strcmp(opt, "--audit") || !strcmp(opt, "--cgroup-parent") ||
                   !strcmp(opt, "--workspace") || !strcmp(opt, "--workspace-parent") ||
                   !strcmp(opt, "--workspace-diff") || !strcmp(opt, "--workspace-export")) {
            if (*val != '/') return bad("path must be absolute", val);
            if (!strcmp(opt, "--audit")) cfg.audit = val;
            else if (!strcmp(opt, "--cgroup-parent")) cfg.cgroup_parent = val;
            else if (!strcmp(opt, "--workspace")) workspace_source = val;
            else if (!strcmp(opt, "--workspace-parent")) workspace_parent = val;
            else if (!strcmp(opt, "--workspace-diff")) cfg.workspace_diff = val;
            else cfg.workspace_export = val;
        } else if (!strcmp(opt, "--env")) {
            if (!env_valid(val)) return bad("invalid environment assignment", val);
            if (cfg.env_count == CINCTA_MAX_ENV) return bad("too many environment variables", opt);
            size_t len = (size_t)(strchr(val, '=') - val) + 1;
            bool replaced = false;
            for (size_t j = 0; j < cfg.env_count; ++j) {
                if (!strncmp(cfg.env[j], val, len)) { cfg.env[j] = argv[i]; replaced = true; break; }
            }
            if (!replaced) cfg.env[cfg.env_count++] = argv[i];
        } else {
            unsigned n;
            if (!number(val, &n)) return bad("invalid numeric option", val);
            if (!strcmp(opt, "--timeout-ms")) cfg.timeout_ms = n;
            else if (!strcmp(opt, "--memory-mb") && n) cfg.memory_mb = n;
            else if (!strcmp(opt, "--cpu-seconds") && n) cfg.cpu_seconds = n;
            else if (!strcmp(opt, "--processes") && n) cfg.processes = n;
            else if (!strcmp(opt, "--nofile") && n >= 16) cfg.nofile = n;
            else if (!strcmp(opt, "--tree-memory-mb") && n) cfg.tree_memory_mb = n;
            else if (!strcmp(opt, "--tree-pids") && n) cfg.tree_pids = n;
            else if (!strcmp(opt, "--tree-cpu-percent") && n && n <= 1000000) cfg.tree_cpu_percent = n;
            else if (!strcmp(opt, "--tree-cpu-ms") && n) cfg.tree_cpu_ms = n;
            else if (!strcmp(opt, "--workspace-max-files") && n) workspace_files = n;
            else if (!strcmp(opt, "--workspace-max-bytes") && n) workspace_bytes = n;
            else if (!strcmp(opt, "--audit-max-bytes") && n) cfg.audit_max_bytes = n;
            else if (!strcmp(opt, "--audit-max-records") && n) cfg.audit_max_records = n;
            else return bad("unknown option or invalid limit", opt);
        }
    }
    if (!cfg.command) return bad("missing command separator", "--");
    if (net_count && network_explicit && !cfg.network_allowlist) return bad("network rules require allowlist mode", "--network");
    if (net_count) cfg.network_allowlist = true;
    if (cfg.network_allowlist && !net_count) return bad("allowlist mode requires rules", "--allow-net");
    if (cfg.audit_syscalls && !cfg.audit) return bad("syscall audit requires output", "--audit");
    if (!workspace_source && (workspace_parent || cfg.workspace_diff || cfg.workspace_export || cfg.workspace_keep || cfg.workspace_exec || workspace_files || workspace_bytes))
        return bad("workspace options require source", "--workspace");
    if (workspace_source && cwd_explicit) return bad("workspace selects cwd", "--cwd");
    if (!cfg.cgroup_parent && (cfg.tree_memory_mb || cfg.tree_pids || cfg.tree_cpu_percent || cfg.tree_cpu_ms))
        return bad("tree limits require explicit delegation", "--cgroup-parent");
    uint64_t preparation_started = milliseconds();
    char error[512] = {0}, canonical[PATH_MAX], protected[PATH_MAX];
    int code = 125;
    if (workspace_source) {
        if (!realpath(workspace_source, protected)) return bad("workspace source", strerror(errno));
        struct filesystem_path source_key, grant_key;
        if (filesystem_path_open(protected, &source_key) < 0)
            return bad("workspace layout", "source mount identity is unavailable");
        for (size_t i = 0; i < cfg.rule_count; ++i)
            if (cfg.rules[i].mode == PATH_RW) return bad("workspace mode permits writes only inside its snapshot", cfg.rules[i].path);
        for (int fd = 0; fd < 3; ++fd) {
            struct stat st;
            if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY)
                return bad("workspace writable stdio must be a stream, not an external regular file", "stdio");
        }
        for (size_t i = 0; i < cfg.rule_count; ++i) {
            if (!realpath(cfg.rules[i].path, canonical) || filesystem_path_open_flags(canonical, 0, &grant_key) < 0)
                return bad("workspace grant identity", cfg.rules[i].path);
            if (overlap(canonical, protected) || filesystem_overlap(&source_key, &grant_key))
                return bad("grant overlaps original workspace", cfg.rules[i].path);
        }
        if (cfg.rule_count + (cfg.workspace_exec ? 2 : 1) > CINCTA_MAX_RULES) return bad("no slot for workspace rules", "--workspace");
        char parent[PATH_MAX];
        if (!realpath(workspace_parent ? workspace_parent : "/tmp", parent) || beneath(protected, parent))
            return bad("workspace parent must exist outside source", workspace_parent ? workspace_parent : "/tmp");
        if (workspace_layout_safe(protected, parent) < 0)
            return bad("workspace layout", "parent aliases source, source contains a submount, or mount metadata is unavailable");
        if (preparation_start(&workspace, &resources, workspace_parent, cfg.caller_fd, &guard, error, sizeof(error)) < 0)
            return bad("preparation guardian", error);
        cfg.preparation = &guard; cfg.resources = resources;
        if (workspace_prepare(workspace_source, preparation_workspace_parent(&guard), workspace_files, workspace_bytes, workspace, error, sizeof(error)) < 0) {
            bad("workspace preparation", error); goto done;
        }
        cfg.workspace = workspace; cfg.cwd = workspace->tree;
        struct filesystem_path private_key;
        if (filesystem_path_open(workspace->root, &private_key) < 0) {
            bad("workspace private identity", strerror(errno)); goto done;
        }
        for (size_t i = 0; i < cfg.rule_count; ++i) {
            if (!realpath(cfg.rules[i].path, canonical) || filesystem_path_open_flags(canonical, 0, &grant_key) < 0) {
                bad("workspace grant identity", cfg.rules[i].path); goto done;
            }
            if (overlap(canonical, workspace->root) || filesystem_overlap(&private_key, &grant_key)) {
                bad("grant exposes private workspace", cfg.rules[i].path); goto done;
            }
        }
        cfg.rules[cfg.rule_count++] = (struct path_rule){workspace->tree, PATH_RW};
        if (cfg.workspace_exec) cfg.rules[cfg.rule_count++] = (struct path_rule){workspace->tree, PATH_RX};
    }
    if (cfg.cgroup_parent && !cfg.preparation) {
        if (preparation_start(&workspace, &resources, NULL, cfg.caller_fd, &guard, error, sizeof(error)) < 0) {
            bad("preparation guardian", error); goto done;
        }
        cfg.preparation = &guard; cfg.resources = resources;
    }
    if (trusted_output(&cfg, cfg.result) < 0 || trusted_output(&cfg, cfg.audit) < 0 ||
        trusted_output(&cfg, cfg.workspace_diff) < 0 || trusted_output(&cfg, cfg.workspace_export) < 0) {
        bad("outputs must have existing trusted parents outside writable grants", "result/audit/workspace output"); goto done;
    }
    if (cfg.cgroup_parent && realpath(cfg.cgroup_parent, protected))
        for (size_t i = 0; i < cfg.rule_count; ++i)
            if (cfg.rules[i].mode == PATH_RW && realpath(cfg.rules[i].path, canonical) && overlap(canonical, protected)) {
                bad("writable grant exposes cgroup delegation", cfg.rules[i].path); goto done;
            }
    /* DNS/NSS can block independently of workspace/cgroup preparation. Keep
     * an ancestor alive to cancel it when the original caller exits. */
    if (cfg.network_allowlist && !cfg.preparation) {
        if (preparation_start(&workspace, &resources, NULL, cfg.caller_fd, &guard, error, sizeof(error)) < 0) {
            bad("preparation guardian", error); goto done;
        }
        cfg.preparation = &guard; cfg.resources = resources;
    }
    if (cfg.network_allowlist && network_prepare(net_rules, net_count, &cfg.network, error, sizeof(error)) < 0) {
        bad("network policy", error); goto done;
    }
    if (security_pin_policy(&cfg, error, sizeof(error)) < 0) { bad("pin filesystem policy", error); goto done; }
    if (trusted_output(&cfg, cfg.result) < 0 || trusted_output(&cfg, cfg.audit) < 0 ||
        trusted_output(&cfg, cfg.workspace_diff) < 0 || trusted_output(&cfg, cfg.workspace_export) < 0) {
        snprintf(error, sizeof(error), "output directory aliases an authorized writable object, source or snapshot");
        bad("trusted output identity", error); goto done;
    }
    if (cfg.metadata && syscall(452, -1, "", 0, AT_EMPTY_PATH) < 0 && errno != EBADF) {
        snprintf(error, sizeof(error), "metadata requires usable fchmodat2(AT_EMPTY_PATH): %s", strerror(errno));
        bad("metadata capability", error); goto done;
    }
    if (cgroup_grants_safe(&cfg) < 0) {
        snprintf(error, sizeof(error), "writable grant exposes a cgroup2 mount or mount metadata is unavailable");
        bad("cgroup isolation", error); goto done;
    }
    if (caller_alive(cfg.caller_fd) != 1) {
        bad("caller exited during preparation", "execution was not started"); code = 143; goto done;
    }
    /* No trusted output is created until all object-identity and mount checks
     * pass. An unsafe output alias must not even create an empty source file. */
    if (result_open(&cfg) < 0) { bad("result creation", strerror(errno)); goto done; }
    if (broker_open(&cfg, error, sizeof(error)) < 0) { bad("audit initialization", error); goto done; }
    if ((cfg.preparation ? preparation_resources(&guard, &cfg, error, sizeof(error))
                         : resource_prepare(&cfg, resources, error, sizeof(error))) < 0) {
        bad("tree resources", error); goto done;
    }
    cfg.resources = resources;
    cfg.preparation_ms = milliseconds() - preparation_started;
    code = supervise(&cfg);
done:;
    bool startup_result = result_get_fd() >= 0, cleanup_complete = true;
    char startup_error[sizeof(error)], cleanup_error[512] = {0};
    snprintf(startup_error, sizeof(startup_error), "%s", error[0] ? error : "preparation failed");
    if (startup_result) cfg.preparation_ms = milliseconds() - preparation_started;
    if (cfg.workspace && (!cfg.state || !cfg.state->workspace_finished)) {
        if ((code != 0 || !cfg.workspace_keep) && workspace_discard(workspace, cleanup_error, sizeof(cleanup_error)) < 0) {
            bad("workspace cleanup", cleanup_error); cleanup_complete = false; code = 125;
            if (cfg.state) cfg.state->workspace_failed = true;
        }
    }
    if (resources->enabled && !resources->removed && !(cfg.state && cfg.state->resource_removed) && resource_finish(resources, cleanup_error, sizeof(cleanup_error)) < 0) {
        bad("resource cleanup", cleanup_error); cleanup_complete = false; code = 125;
    }
    /* preparation_finish unmaps its shared contexts. Preserve their final
     * observed state for startup results, which must follow every cleanup. */
    if (guard.shared) {
        const char *old_tree = workspace->tree;
        local_workspace = *workspace; local_resources = *resources;
        if (cfg.cwd == old_tree) cfg.cwd = local_workspace.tree;
        for (size_t i = 0; i < cfg.rule_count; ++i)
            if (cfg.rules[i].path == old_tree) cfg.rules[i].path = local_workspace.tree;
        workspace = &local_workspace; resources = &local_resources;
        if (cfg.workspace) cfg.workspace = workspace;
        if (cfg.resources) cfg.resources = resources;
    }
    if (preparation_finish(&guard, cleanup_error, sizeof(cleanup_error)) < 0) {
        bad("preparation cleanup", cleanup_error); cleanup_complete = false; code = 125;
    }
    if (cfg.state && cfg.state->audit_fd >= 0 && !cfg.state->audit_finished) {
        if (broker_event(&cfg, "finish", NULL, "setup_error", 125, 0) < 0 || fsync(cfg.state->audit_fd) < 0)
            cfg.state->audit_failed = true;
        if (cfg.state->audit_failed) code = 125;
    }
    if (startup_result) {
        char final_error[1200];
        snprintf(final_error, sizeof(final_error), "%s%s%s", startup_error,
            cleanup_complete ? "" : "; cleanup: ", cleanup_complete ? "" : cleanup_error);
        const char *stage = cleanup_complete ? "configuration" : "configuration_cleanup";
        if (cfg.state && cfg.state->audit_failed) stage = "audit";
        struct capabilities detected = {0};
        if (result_write(&cfg, &detected, "setup_error", stage, final_error,
                         125, 0, false, false, cleanup_complete,
                         milliseconds() - preparation_started - cfg.preparation_ms) < 0)
            bad("result write failed", strerror(errno));
        code = 125;
    }
    network_destroy(cfg.network); broker_close(&cfg); security_release_policy(&cfg);
    if (cfg.caller_fd >= 0) close(cfg.caller_fd);
    return code;
}
