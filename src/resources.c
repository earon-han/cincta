#define _GNU_SOURCE
#include "resources.h"
#include "cincta.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

static int failure(char *error, size_t size, const char *fmt, ...)
{
    int saved = errno;
    va_list ap;
    va_start(ap, fmt);
    if (size) vsnprintf(error, size, fmt, ap);
    va_end(ap);
    errno = saved;
    return -1;
}

static int cgroup_directory(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct statfs fs;
    if (fstatfs(fd, &fs) < 0) { int saved = errno; close(fd); errno = saved; return -1; }
    if ((unsigned long)fs.f_type != (unsigned long)CGROUP2_SUPER_MAGIC) {
        close(fd); errno = ENODEV; return -1;
    }
    return fd;
}

static int reopen(const struct resource_ctx *ctx)
{
    int fd = cgroup_directory(ctx->path);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { int saved = errno; close(fd); errno = saved; return -1; }
    if (st.st_dev != ctx->device || st.st_ino != ctx->inode) {
        close(fd); errno = ESTALE; return -1;
    }
    return fd;
}

static int write_control(int dir, const char *name, const char *value)
{
    int fd = openat(dir, name, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t length = strlen(value);
    ssize_t n;
    do { n = write(fd, value, length); } while (n < 0 && errno == EINTR);
    int saved = errno;
    if (n != (ssize_t)length) saved = n < 0 ? saved : EIO;
    int result = n == (ssize_t)length ? 0 : -1;
    if (close(fd) < 0 && result == 0) { saved = errno; result = -1; }
    errno = saved;
    return result;
}

static int read_control(int dir, const char *name, char *buf, size_t size)
{
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, buf + used, size - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { int saved = errno; close(fd); errno = saved; return -1; }
        if (!n) break;
        used += (size_t)n;
        if (used == size - 1) { close(fd); errno = EOVERFLOW; return -1; }
    }
    close(fd);
    buf[used] = '\0';
    return 0;
}

static int read_number(int dir, const char *name, uint64_t *number)
{
    char text[128], *end;
    if (read_control(dir, name, text, sizeof(text)) < 0) return -1;
    errno = 0;
    if (text[0] < '0' || text[0] > '9') { errno = EINVAL; return -1; }
    unsigned long long value = strtoull(text, &end, 10);
    if (errno) return -1;
    while (*end == ' ' || *end == '\t' || *end == '\n') ++end;
    if (*end) { errno = EINVAL; return -1; }
    *number = (uint64_t)value;
    return 0;
}

static bool keyed(const char *text, const char *key, uint64_t *number)
{
    size_t length = strlen(key);
    for (const char *line = text; *line;) {
        if (!strncmp(line, key, length) && line[length] == ' ') {
            char *end;
            errno = 0;
            unsigned long long value = strtoull(line + length + 1, &end, 10);
            if (!errno && end != line + length + 1 && (*end == '\n' || !*end)) {
                *number = (uint64_t)value;
                return true;
            }
            return false;
        }
        const char *next = strchr(line, '\n');
        if (!next) break;
        line = next + 1;
    }
    return false;
}

static int configure_number(int dir, const char *name, uint64_t value,
                            char *error, size_t size)
{
    char text[64];
    snprintf(text, sizeof(text), "%" PRIu64 "\n", value);
    if (write_control(dir, name, text) < 0)
        return failure(error, size, "cgroup %s: %s (controller must be enabled and delegated)", name, strerror(errno));
    uint64_t observed;
    if (read_number(dir, name, &observed) < 0 || observed != value) {
        if (!errno) errno = EIO;
        return failure(error, size, "cgroup %s readback mismatch", name);
    }
    return 0;
}

int resource_prepare(const struct config *cfg, struct resource_ctx *ctx,
                     char *error, size_t error_size)
{
    memset(ctx, 0, sizeof(*ctx));
    bool requested = cfg->cgroup_parent || cfg->tree_memory_mb || cfg->tree_pids ||
                     cfg->tree_cpu_percent || cfg->tree_cpu_ms;
    if (!requested) return 0;
    if (!cfg->cgroup_parent || cfg->cgroup_parent[0] != '/') {
        errno = EINVAL;
        return failure(error, error_size, "tree resource limits require an absolute --cgroup-parent delegated path");
    }
    if (cfg->tree_cpu_percent > 1000000U) {
        errno = EINVAL;
        return failure(error, error_size, "--tree-cpu-percent must be between 1 and 1000000 when requested");
    }
    if (!realpath(cfg->cgroup_parent, ctx->parent))
        return failure(error, error_size, "resolve cgroup parent: %s", strerror(errno));
    int parent = cgroup_directory(ctx->parent);
    if (parent < 0)
        return failure(error, error_size, "cgroup parent must be a writable delegated cgroup v2 directory: %s", strerror(errno));
    char name[96];
    bool created = false;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        uint64_t random;
        ssize_t n;
        do { n = getrandom(&random, sizeof(random), 0); } while (n < 0 && errno == EINTR);
        if (n != (ssize_t)sizeof(random)) { if (n >= 0) errno = EIO; break; }
        snprintf(name, sizeof(name), "cincta-%ld-%016" PRIx64, (long)getpid(), random);
        if (mkdirat(parent, name, 0700) == 0) { created = true; break; }
        if (errno != EEXIST) break;
    }
    if (!created) {
        int saved = errno; close(parent); errno = saved;
        return failure(error, error_size, "create delegated cgroup child: %s", strerror(errno));
    }
    int directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        int saved = errno; unlinkat(parent, name, AT_REMOVEDIR); close(parent); errno = saved;
        return failure(error, error_size, "open private cgroup: %s", strerror(errno));
    }
    struct stat st;
    int written = snprintf(ctx->path, sizeof(ctx->path), "%s%s%s", ctx->parent,
                           !strcmp(ctx->parent, "/") ? "" : "/", name);
    if (written < 0 || (size_t)written >= sizeof(ctx->path) || fstat(directory, &st) < 0) {
        int saved = errno ? errno : ENAMETOOLONG;
        close(directory); unlinkat(parent, name, AT_REMOVEDIR); close(parent); errno = saved;
        return failure(error, error_size, "identify private cgroup: %s", strerror(errno));
    }
    ctx->device = st.st_dev; ctx->inode = st.st_ino;
    ctx->enabled = true;
    ctx->memory_mb = cfg->tree_memory_mb; ctx->pids_max = cfg->tree_pids;
    ctx->cpu_percent = cfg->tree_cpu_percent; ctx->cpu_budget_ms = cfg->tree_cpu_ms;
    int result = -1;
    if (cfg->tree_memory_mb &&
        (configure_number(directory, "memory.max", (uint64_t)cfg->tree_memory_mb * 1024 * 1024, error, error_size) < 0 ||
         configure_number(directory, "memory.oom.group", 1, error, error_size) < 0)) goto done;
    if (cfg->tree_memory_mb && faccessat(directory, "memory.swap.max", F_OK, 0) == 0) {
        if (configure_number(directory, "memory.swap.max", 0, error, error_size) < 0) goto done;
        ctx->swap_disabled = true;
    }
    if (cfg->tree_pids && configure_number(directory, "pids.max", cfg->tree_pids, error, error_size) < 0) goto done;
    if (cfg->tree_cpu_percent) {
        char text[96], observed[128];
        uint64_t quota = (uint64_t)cfg->tree_cpu_percent * 1000;
        snprintf(text, sizeof(text), "%" PRIu64 " 100000\n", quota);
        if (write_control(directory, "cpu.max", text) < 0) {
            failure(error, error_size, "cgroup cpu.max: %s (cpu controller must be enabled and delegated)", strerror(errno));
            goto done;
        }
        unsigned long long q, period;
        if (read_control(directory, "cpu.max", observed, sizeof(observed)) < 0 ||
            sscanf(observed, "%llu %llu", &q, &period) != 2 || q != quota || period != 100000) {
            errno = EIO; failure(error, error_size, "cgroup cpu.max readback mismatch"); goto done;
        }
    }
    close(directory); directory = -1;
    if (resource_sample(ctx, error, error_size) < 0) goto done;
    result = 0;
done:;
    int saved = errno;
    if (directory >= 0) close(directory);
    if (result < 0 && unlinkat(parent, name, AT_REMOVEDIR) == 0) {
        ctx->enabled = false; ctx->removed = true;
    }
    close(parent); errno = saved;
    return result;
}

int resource_attach(struct resource_ctx *ctx, pid_t pid,
                    char *error, size_t error_size)
{
    if (!ctx->enabled || ctx->removed) return 0;
    if (pid <= 0) { errno = EINVAL; return failure(error, error_size, "invalid payload PID for cgroup attach"); }
    int directory = reopen(ctx);
    if (directory < 0) return failure(error, error_size, "open cgroup for attach: %s", strerror(errno));
    char text[64];
    snprintf(text, sizeof(text), "%ld\n", (long)pid);
    if (write_control(directory, "cgroup.procs", text) < 0) {
        int saved = errno; close(directory); errno = saved;
        return failure(error, error_size, "attach payload to delegated cgroup: %s (source/destination ancestor and cgroup namespace permissions are required)", strerror(errno));
    }
    int fd = openat(directory, "cgroup.procs", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    close(directory);
    if (fd < 0) return failure(error, error_size, "verify cgroup membership: %s", strerror(errno));
    FILE *f = fdopen(fd, "r");
    if (!f) { int saved = errno; close(fd); errno = saved; return failure(error, error_size, "verify cgroup membership: %s", strerror(errno)); }
    long observed;
    bool found = false;
    while (fscanf(f, "%ld", &observed) == 1) if (observed == (long)pid) { found = true; break; }
    int failed = ferror(f); fclose(f);
    if (!found || failed) { errno = EIO; return failure(error, error_size, "payload cgroup membership was not confirmed before exec"); }
    ctx->populated = true;
    return 0;
}

int resource_kill(struct resource_ctx *ctx, char *error, size_t error_size)
{
    if (!ctx->enabled || ctx->removed) return 0;
    int directory = reopen(ctx);
    if (directory < 0) return failure(error, error_size, "open cgroup for kill: %s", strerror(errno));
    int result = write_control(directory, "cgroup.kill", "1\n");
    int saved = errno;
    close(directory); errno = saved;
    if (result == 0) { ctx->kill_supported = true; return 0; }
    if (errno == ENOENT) { ctx->kill_supported = false; return 0; }
    return failure(error, error_size, "cgroup.kill failed: %s", strerror(errno));
}

int resource_sample(struct resource_ctx *ctx, char *error, size_t error_size)
{
    if (!ctx->enabled || ctx->removed) return 0;
    int directory = reopen(ctx);
    if (directory < 0) return failure(error, error_size, "open cgroup for statistics: %s", strerror(errno));
    char text[4096];
    int result = -1;
    if (read_control(directory, "cgroup.events", text, sizeof(text)) < 0) goto fail;
    uint64_t populated;
    if (!keyed(text, "populated", &populated)) { errno = EIO; goto fail; }
    ctx->populated = populated != 0;
    if (read_control(directory, "cpu.stat", text, sizeof(text)) < 0 ||
        !keyed(text, "usage_usec", &ctx->cpu_usage_usec)) { if (!errno) errno = EIO; goto fail; }
    (void)keyed(text, "user_usec", &ctx->cpu_user_usec);
    (void)keyed(text, "system_usec", &ctx->cpu_system_usec);
    (void)keyed(text, "nr_throttled", &ctx->cpu_nr_throttled);
    (void)keyed(text, "throttled_usec", &ctx->cpu_throttled_usec);
    uint64_t value;
    if (read_number(directory, "memory.current", &value) == 0) {
        ctx->memory_available = true; ctx->memory_current = value;
        if (value > ctx->memory_peak) ctx->memory_peak = value;
        if (read_number(directory, "memory.peak", &value) == 0) {
            ctx->memory_peak_supported = true; ctx->memory_peak = value;
        } else if (errno != ENOENT) goto fail;
        if (read_control(directory, "memory.events", text, sizeof(text)) < 0) goto fail;
        (void)keyed(text, "oom", &ctx->memory_oom);
        (void)keyed(text, "oom_kill", &ctx->memory_oom_kill);
    } else if (errno != ENOENT || ctx->memory_mb) goto fail;
    if (read_number(directory, "pids.current", &value) == 0) {
        ctx->pids_available = true; ctx->pids_current = value;
        if (value > ctx->pids_peak) ctx->pids_peak = value;
        if (read_number(directory, "pids.peak", &value) == 0) {
            ctx->pids_peak_supported = true; ctx->pids_peak = value;
        } else if (errno != ENOENT) goto fail;
        if (read_control(directory, "pids.events", text, sizeof(text)) < 0) goto fail;
        (void)keyed(text, "max", &ctx->pids_limit_hits);
    } else if (errno != ENOENT || ctx->pids_max) goto fail;
    ctx->kill_supported = faccessat(directory, "cgroup.kill", F_OK, 0) == 0;
    result = 0;
    goto done;
fail:
    failure(error, error_size, "read cgroup statistics: %s", strerror(errno));
done:;
    int saved = errno; close(directory); errno = saved;
    return result;
}

bool resource_budget_exceeded(const struct resource_ctx *ctx,
                              const struct config *cfg)
{
    return ctx->enabled && cfg->tree_cpu_ms &&
           ctx->cpu_usage_usec >= (uint64_t)cfg->tree_cpu_ms * 1000;
}

int resource_finish(struct resource_ctx *ctx, char *error, size_t error_size)
{
    if (!ctx->enabled || ctx->removed) return 0;
    if (resource_sample(ctx, error, error_size) < 0) return -1;
    if (ctx->populated) {
        errno = EBUSY;
        return failure(error, error_size, "private cgroup still contains live descendants; cleanup is incomplete");
    }
    int directory = reopen(ctx);
    if (directory < 0) return failure(error, error_size, "identify cgroup before removal: %s", strerror(errno));
    int result = rmdir(ctx->path);
    int saved = errno; close(directory); errno = saved;
    if (result < 0) return failure(error, error_size, "remove private cgroup: %s", strerror(errno));
    ctx->removed = true;
    return 0;
}
