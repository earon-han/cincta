#define _GNU_SOURCE
#include "workspace.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define WORKSPACE_MAX_DEPTH 128
struct budget { uint64_t files, bytes, max_files, max_bytes; };
struct entry { char *path; char *link; struct stat st; };
struct manifest { struct entry *items; size_t count, capacity; struct budget budget; };
struct change { const struct entry *before, *after; };

static int failure(char *error, size_t size, const char *fmt, ...)
{
    int saved = errno;
    va_list args;
    va_start(args, fmt);
    if (size) vsnprintf(error, size, fmt, args);
    va_end(args);
    errno = saved;
    return -1;
}

static bool beneath(const char *root, const char *path)
{
    size_t n = strlen(root);
    return !strncmp(root, path, n) && (n == 1 || path[n] == 0 || path[n] == '/');
}

static bool valid_utf8(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        uint32_t c = *p++;
        unsigned n;
        if (c < 0x80) continue;
        if (c >= 0xc2 && c <= 0xdf) { n = 1; c &= 0x1f; }
        else if (c >= 0xe0 && c <= 0xef) { n = 2; c &= 0x0f; }
        else if (c >= 0xf0 && c <= 0xf4) { n = 3; c &= 0x07; }
        else return false;
        unsigned remaining = n;
        while (remaining--) {
            if ((*p & 0xc0) != 0x80) return false;
            c = (c << 6) | (*p++ & 0x3f);
        }
        if ((n == 1 && c < 0x80) || (n == 2 && c < 0x800) ||
            (n == 3 && c < 0x10000) || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return false;
    }
    return true;
}

static int joined(char *out, size_t size, const char *parent, const char *name)
{
    int n = snprintf(out, size, "%s%s%s", parent, *parent ? "/" : "", name);
    if (n < 0 || (size_t)n >= size) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

static bool unchanged(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

/* A relative target must stay within the copied root after lexical dot/dotdot
 * normalization from its link's parent. Every link is checked independently;
 * directory traversal itself never follows a link. */
static bool safe_link(int root, const char *relative, const char *target)
{
    if (!*target || *target == '/' || !valid_utf8(target)) return false;
    size_t depth = 0;
    for (const char *p = relative; *p; ++p) if (*p == '/') ++depth;
    const char *p = target;
    while (*p) {
        while (*p == '/') ++p;
        const char *end = p;
        while (*end && *end != '/') ++end;
        size_t n = (size_t)(end - p);
        if (n == 2 && p[0] == '.' && p[1] == '.') {
            if (!depth) return false;
            --depth;
        } else if (n && !(n == 1 && p[0] == '.')) ++depth;
        p = end;
    }
    /* Lexical confinement alone is insufficient: an earlier component may
     * itself be a symlink changing what a later '..' resolves to. */
    struct open_how how = {.flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS};
    int fd = (int)syscall(SYS_openat2, root, relative, &how, sizeof(how));
    if (fd < 0) return false;
    close(fd);
    return true;
}

static int account(struct budget *b, const struct stat *st)
{
    if (b->files >= b->max_files) { errno = EFBIG; return -1; }
    ++b->files;
    if (S_ISREG(st->st_mode)) {
        if (st->st_size < 0 || (uint64_t)st->st_size > b->max_bytes - b->bytes) { errno = EFBIG; return -1; }
        b->bytes += (uint64_t)st->st_size;
    }
    return 0;
}

static int write_all(int fd, const void *buffer, size_t size)
{
    const unsigned char *p = buffer;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; size -= (size_t)n;
    }
    return 0;
}

static int copy_regular(int src, int dst, const struct stat *expected)
{
    unsigned char buffer[65536];
    uint64_t total = 0;
    for (;;) {
        ssize_t n = read(src, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        if (n == 0) break;
        total += (uint64_t)n;
        if (total > (uint64_t)expected->st_size) { errno = EBUSY; return -1; }
        if (write_all(dst, buffer, (size_t)n) < 0) return -1;
    }
    struct stat actual;
    if (fstat(src, &actual) < 0) return -1;
    if (total != (uint64_t)expected->st_size || !unchanged(expected, &actual)) { errno = EBUSY; return -1; }
    struct timespec times[2] = {expected->st_atim, expected->st_mtim};
    if (fchmod(dst, expected->st_mode & 0777) < 0 || futimens(dst, times) < 0) return -1;
    return 0;
}

static int copy_dir(int anchor, int src, int dst, const char *relative, unsigned depth,
                    struct budget *budget, char *error, size_t error_size)
{
    if (depth > WORKSPACE_MAX_DEPTH) { errno = ELOOP; return failure(error, error_size, "workspace depth exceeds %u", WORKSPACE_MAX_DEPTH); }
    struct stat initial;
    if (fstat(src, &initial) < 0) return failure(error, error_size, "stat directory: %s", strerror(errno));
    int duplicate = dup(src);
    if (duplicate < 0) return failure(error, error_size, "duplicate directory: %s", strerror(errno));
    DIR *dir = fdopendir(duplicate);
    if (!dir) { close(duplicate); return failure(error, error_size, "read directory: %s", strerror(errno)); }
    rewinddir(dir);
    int rc = -1;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) { if (!errno) rc = 0; break; }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char rel[PATH_MAX];
        if (!valid_utf8(de->d_name) || joined(rel, sizeof(rel), relative, de->d_name) < 0) {
            errno = EINVAL; failure(error, error_size, "workspace paths must be bounded UTF-8"); break;
        }
        struct stat st;
        if (fstatat(src, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) { failure(error, error_size, "stat '%s': %s", rel, strerror(errno)); break; }
        if (account(budget, &st) < 0) { failure(error, error_size, "workspace file/byte limit exceeded at '%s'", rel); break; }
        if (S_ISDIR(st.st_mode)) {
            int input = openat(src, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (input < 0) { failure(error, error_size, "open directory '%s': %s", rel, strerror(errno)); break; }
            struct stat pinned;
            if (fstat(input, &pinned) < 0 || !unchanged(&st, &pinned) || mkdirat(dst, de->d_name, 0700) < 0) {
                close(input); errno = EBUSY; failure(error, error_size, "directory changed or cannot be created: '%s'", rel); break;
            }
            int output = openat(dst, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            int copied = output >= 0 ? copy_dir(anchor, input, output, rel, depth + 1, budget, error, error_size) : -1;
            close(input);
            if (output >= 0) close(output);
            if (copied < 0) break;
        } else if (S_ISREG(st.st_mode)) {
            int input = openat(src, de->d_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
            if (input < 0) { failure(error, error_size, "open file '%s': %s", rel, strerror(errno)); break; }
            struct stat pinned;
            if (fstat(input, &pinned) < 0 || !S_ISREG(pinned.st_mode) || !unchanged(&st, &pinned)) {
                close(input); errno = EBUSY; failure(error, error_size, "file changed during snapshot: '%s'", rel); break;
            }
            int output = openat(dst, de->d_name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            int copied = output >= 0 ? copy_regular(input, output, &pinned) : -1;
            int saved = errno;
            close(input); if (output >= 0 && close(output) < 0 && copied == 0) { copied = -1; saved = errno; }
            if (copied < 0) { errno = saved; failure(error, error_size, "copy '%s': %s", rel, strerror(errno)); break; }
        } else if (S_ISLNK(st.st_mode)) {
            char target[PATH_MAX];
            ssize_t n = readlinkat(src, de->d_name, target, sizeof(target));
            struct stat actual;
            if (n < 0 || (size_t)n >= sizeof(target) || fstatat(src, de->d_name, &actual, AT_SYMLINK_NOFOLLOW) < 0 || !unchanged(&st, &actual)) {
                errno = EBUSY; failure(error, error_size, "symlink changed during snapshot: '%s'", rel); break;
            }
            target[n] = 0;
            if (!safe_link(anchor, rel, target)) { errno = EINVAL; failure(error, error_size, "absolute/escaping/dangling symlink rejected: '%s'", rel); break; }
            struct timespec times[2] = {st.st_atim, st.st_mtim};
            if (symlinkat(target, dst, de->d_name) < 0 || utimensat(dst, de->d_name, times, AT_SYMLINK_NOFOLLOW) < 0) {
                failure(error, error_size, "copy symlink '%s': %s", rel, strerror(errno)); break;
            }
        } else {
            errno = EINVAL; failure(error, error_size, "special file rejected: '%s'", rel); break;
        }
    }
    int saved = errno;
    closedir(dir);
    if (rc == 0) {
        struct stat actual;
        if (fstat(src, &actual) < 0 || !unchanged(&initial, &actual)) {
            errno = EBUSY; return failure(error, error_size, "directory changed during snapshot: '%s'", relative);
        }
        struct timespec times[2] = {initial.st_atim, initial.st_mtim};
        if (fchmod(dst, initial.st_mode & 0777) < 0 || futimens(dst, times) < 0)
            return failure(error, error_size, "preserve directory metadata: %s", strerror(errno));
    }
    errno = saved;
    return rc;
}

/* A payload may leave a directory mode 000. O_PATH pins the directory before
 * chmod via real procfs; no attacker-supplied symlink is followed. */
static int open_owned_dir(int parent, const char *name)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 || errno != EACCES) return fd;
    int pin = openat(parent, name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pin < 0) return -1;
    struct stat st;
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", pin);
    if (fstat(pin, &st) < 0 || st.st_uid != geteuid() || chmod(proc, 0700) < 0) { close(pin); return -1; }
    fd = openat(pin, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(pin);
    return fd;
}

static int remove_contents(int fd, unsigned depth)
{
    if (depth > WORKSPACE_MAX_DEPTH + 2) { errno = ELOOP; return -1; }
    if (fchmod(fd, 0700) < 0) return -1;
    int duplicate = dup(fd);
    if (duplicate < 0) return -1;
    DIR *dir = fdopendir(duplicate);
    if (!dir) { close(duplicate); return -1; }
    rewinddir(dir);
    int rc = 0;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) { if (errno) rc = -1; break; }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        struct stat st;
        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) { rc = -1; break; }
        if (S_ISDIR(st.st_mode)) {
            int child = open_owned_dir(fd, de->d_name);
            if (child < 0) { rc = -1; break; }
            rc = remove_contents(child, depth + 1);
            int saved = errno;
            close(child);
            if (!rc) rc = unlinkat(fd, de->d_name, AT_REMOVEDIR);
            else errno = saved;
        } else rc = unlinkat(fd, de->d_name, 0);
        if (rc < 0) break;
    }
    int saved = errno;
    closedir(dir); errno = saved;
    return rc;
}

static int pinned_root(const struct workspace_ctx *ctx)
{
    int fd = open(ctx->root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) < 0 || st.st_dev != ctx->root_dev || st.st_ino != ctx->root_ino || st.st_uid != geteuid()) {
        close(fd); errno = ESTALE; return -1;
    }
    return fd;
}

int workspace_discard(struct workspace_ctx *ctx, char *error, size_t size)
{
    if (!ctx->prepared) return 0;
    int root = pinned_root(ctx);
    if (root < 0) return failure(error, size, "private workspace identity changed: %s", strerror(errno));
    int rc = remove_contents(root, 0), saved = errno;
    close(root);
    if (rc == 0) rc = rmdir(ctx->root);
    else errno = saved;
    if (rc < 0) { ctx->retained = true; return failure(error, size, "discard workspace: %s", strerror(errno)); }
    ctx->prepared = false; ctx->retained = false;
    return 0;
}

int workspace_prepare(const char *source, const char *parent, uint64_t max_files,
                      uint64_t max_bytes, struct workspace_ctx *ctx, char *error, size_t size)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->max_files = max_files ? max_files : WORKSPACE_DEFAULT_MAX_FILES;
    ctx->max_bytes = max_bytes ? max_bytes : WORKSPACE_DEFAULT_MAX_BYTES;
    if (!parent) parent = "/tmp";
    if (!source || *source != '/' || *parent != '/' || !valid_utf8(source) || !valid_utf8(parent)) {
        errno = EINVAL; return failure(error, size, "workspace source/parent require absolute UTF-8 directories");
    }
    int input = open(source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (input < 0) return failure(error, size, "open workspace source: %s", strerror(errno));
    char base[PATH_MAX];
    if (!realpath(source, ctx->source) || !realpath(parent, base)) {
        int saved = errno; close(input); errno = saved; return failure(error, size, "resolve workspace paths: %s", strerror(errno));
    }
    if (beneath(ctx->source, base)) {
        close(input); errno = EINVAL; return failure(error, size, "workspace parent must be outside source");
    }
    if (joined(ctx->root, sizeof(ctx->root), base, "cincta-workspace-XXXXXX") < 0 || !mkdtemp(ctx->root)) {
        int saved = errno; close(input); errno = saved; return failure(error, size, "create private workspace: %s", strerror(errno));
    }
    int root = open(ctx->root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat identity;
    if (root < 0 || fstat(root, &identity) < 0) {
        int saved = errno; if (root >= 0) close(root); close(input); rmdir(ctx->root); errno = saved;
        return failure(error, size, "open private workspace: %s", strerror(errno));
    }
    ctx->root_dev = identity.st_dev; ctx->root_ino = identity.st_ino; ctx->prepared = true;
    int baseline = -1, tree = -1, rc = -1;
    struct budget budget = {0, 0, ctx->max_files, ctx->max_bytes};
    if (mkdirat(root, "baseline", 0700) < 0 || mkdirat(root, "tree", 0700) < 0 ||
        joined(ctx->tree, sizeof(ctx->tree), ctx->root, "tree") < 0) {
        failure(error, size, "create workspace trees: %s", strerror(errno)); goto out;
    }
    baseline = openat(root, "baseline", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    tree = openat(root, "tree", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (baseline < 0 || tree < 0) { failure(error, size, "open workspace trees: %s", strerror(errno)); goto out; }
    if (copy_dir(input, input, baseline, "", 0, &budget, error, size) < 0) goto out;
    ctx->copied_files = budget.files; ctx->copied_bytes = budget.bytes;
    budget.files = 0; budget.bytes = 0;
    if (copy_dir(baseline, baseline, tree, "", 0, &budget, error, size) < 0) goto out;
    rc = 0;
out:;
    int saved = errno;
    close(input);
    if (baseline >= 0) close(baseline);
    if (tree >= 0) close(tree);
    close(root);
    if (rc < 0) { char ignored[128]; (void)workspace_discard(ctx, ignored, sizeof(ignored)); }
    errno = saved;
    return rc;
}

static void manifest_free(struct manifest *m)
{
    for (size_t i = 0; i < m->count; ++i) { free(m->items[i].path); free(m->items[i].link); }
    free(m->items);
}

static struct entry *manifest_entry(struct manifest *m, const char *path,
                                    const struct stat *st)
{
    if (m->count == m->capacity) {
        size_t cap = m->capacity ? m->capacity * 2 : 64;
        if (cap < m->capacity || cap > SIZE_MAX / sizeof(*m->items)) { errno = EOVERFLOW; return NULL; }
        struct entry *next = realloc(m->items, cap * sizeof(*m->items));
        if (!next) return NULL;
        m->items = next; m->capacity = cap;
    }
    struct entry *entry = &m->items[m->count];
    memset(entry, 0, sizeof(*entry)); entry->st = *st;
    entry->path = strdup(path);
    if (!entry->path) return NULL;
    ++m->count;
    return entry;
}

static int collect(int anchor, int fd, const char *relative, unsigned depth, struct manifest *m,
                   char *error, size_t size)
{
    if (depth > WORKSPACE_MAX_DEPTH) { errno = ELOOP; return failure(error, size, "workspace diff depth exceeded"); }
    if (depth == 0) {
        struct stat st;
        /* Root metadata belongs in the diff but not in the copied-entry or
         * final-tree budget. It denotes the tree itself, never an extra file. */
        if (fstat(fd, &st) < 0 || !manifest_entry(m, ".", &st))
            return failure(error, size, "collect workspace root metadata: %s", strerror(errno));
    }
    int duplicate = dup(fd);
    if (duplicate < 0) return failure(error, size, "duplicate diff directory: %s", strerror(errno));
    DIR *dir = fdopendir(duplicate);
    if (!dir) { close(duplicate); return failure(error, size, "read diff directory: %s", strerror(errno)); }
    rewinddir(dir);
    int rc = -1;
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) { if (!errno) rc = 0; break; }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char rel[PATH_MAX]; struct stat st;
        if (!valid_utf8(de->d_name) || joined(rel, sizeof(rel), relative, de->d_name) < 0) {
            errno = EINVAL; failure(error, size, "diff paths require bounded UTF-8"); break;
        }
        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0 || account(&m->budget, &st) < 0) {
            failure(error, size, "workspace diff limits/stat failed at '%s': %s", rel, strerror(errno)); break;
        }
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            errno = EINVAL; failure(error, size, "special file in completed workspace: '%s'", rel); break;
        }
        struct entry *entry = manifest_entry(m, rel, &st);
        if (!entry) break;
        if (S_ISLNK(st.st_mode)) {
            char target[PATH_MAX];
            ssize_t n = readlinkat(fd, de->d_name, target, sizeof(target));
            if (n < 0 || (size_t)n >= sizeof(target)) { failure(error, size, "read diff symlink: '%s'", rel); break; }
            target[n] = 0;
            if (!safe_link(anchor, rel, target)) { errno = EINVAL; failure(error, size, "unsafe/dangling symlink in completed workspace: '%s'", rel); break; }
            entry->link = strdup(target);
            if (!entry->link) break;
        } else if (S_ISDIR(st.st_mode)) {
            int child = openat(fd, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) { failure(error, size, "open diff directory '%s': %s", rel, strerror(errno)); break; }
            int sub = collect(anchor, child, rel, depth + 1, m, error, size);
            close(child);
            if (sub < 0) break;
        }
    }
    int saved = errno; closedir(dir); errno = saved;
    if (rc < 0 && size && !*error) failure(error, size, "collect workspace diff: %s", strerror(errno));
    return rc;
}

static int entry_order(const void *a, const void *b)
{
    return strcmp(((const struct entry *)a)->path, ((const struct entry *)b)->path);
}

static int open_relative(int root, const char *path)
{
    char copy[PATH_MAX];
    if (strlen(path) >= sizeof(copy)) { errno = ENAMETOOLONG; return -1; }
    strcpy(copy, path);
    int dir = dup(root);
    if (dir < 0) return -1;
    char *save = NULL, *part = strtok_r(copy, "/", &save);
    while (part) {
        char *next = strtok_r(NULL, "/", &save);
        int fd = openat(dir, part, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (next ? O_DIRECTORY : 0));
        int saved = errno; close(dir);
        if (fd < 0) { errno = saved; return -1; }
        dir = fd; part = next;
    }
    return dir;
}

static int same_entry(int baseline, int tree, const struct entry *a, const struct entry *b)
{
    if ((a->st.st_mode & (S_IFMT | 0777)) != (b->st.st_mode & (S_IFMT | 0777))) return 0;
    if (S_ISLNK(a->st.st_mode)) return !strcmp(a->link, b->link);
    if (a->st.st_mtim.tv_sec != b->st.st_mtim.tv_sec || a->st.st_mtim.tv_nsec != b->st.st_mtim.tv_nsec) return 0;
    if (S_ISDIR(a->st.st_mode)) return 1;
    if (a->st.st_size != b->st.st_size) return 0;
    int left = open_relative(baseline, a->path), right = open_relative(tree, b->path);
    if (left < 0 || right < 0) { int saved = errno; if (left >= 0) close(left); if (right >= 0) close(right); errno = saved; return -1; }
    int same = 1;
    unsigned char x[32768], y[32768];
    for (;;) {
        ssize_t nx, ny;
        do { nx = read(left, x, sizeof(x)); } while (nx < 0 && errno == EINTR);
        do { ny = read(right, y, sizeof(y)); } while (ny < 0 && errno == EINTR);
        if (nx < 0 || ny < 0) { same = -1; break; }
        if (nx != ny || (nx && memcmp(x, y, (size_t)nx))) { same = 0; break; }
        if (!nx) break;
    }
    int saved = errno; close(left); close(right); errno = saved;
    return same;
}

static void json_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(f, "\\%c", *p);
        else if (*p < 32) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

static void json_entry(FILE *f, const struct entry *e)
{
    if (!e) { fputs("null", f); return; }
    const char *type = S_ISDIR(e->st.st_mode) ? "directory" : S_ISREG(e->st.st_mode) ? "file" : "symlink";
    fprintf(f, "{\"type\":\"%s\",\"mode\":%u,\"size\":%llu", type,
        (unsigned)(e->st.st_mode & 0777), (unsigned long long)e->st.st_size);
    if (e->link) { fputs(",\"target\":", f); json_string(f, e->link); }
    fputc('}', f);
}

/* Resolve an existing parent, create only a new final component, and prohibit
 * outputs inside original source or the private snapshot. */
static int output_parent(const struct workspace_ctx *ctx, const char *path,
                         char *name, size_t name_size, char *error, size_t size)
{
    if (!path || *path != '/' || !valid_utf8(path) || strlen(path) >= PATH_MAX) {
        errno = EINVAL; return failure(error, size, "workspace output must be an absolute UTF-8 path");
    }
    char parent[PATH_MAX], canonical[PATH_MAX];
    strcpy(parent, path);
    char *slash = strrchr(parent, '/');
    if (!slash[1] || !strcmp(slash + 1, ".") || !strcmp(slash + 1, "..") || strlen(slash + 1) >= name_size) {
        errno = EINVAL; return failure(error, size, "invalid workspace output final component");
    }
    strcpy(name, slash + 1);
    if (slash == parent) slash[1] = 0; else *slash = 0;
    if (!realpath(parent, canonical)) return failure(error, size, "resolve output parent: %s", strerror(errno));
    if (beneath(ctx->source, canonical) || beneath(ctx->root, canonical)) {
        errno = EINVAL; return failure(error, size, "workspace outputs must be outside source and private root");
    }
    int fd = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return failure(error, size, "open output parent: %s", strerror(errno));
    return fd;
}

int workspace_finish(struct workspace_ctx *ctx, const char *diff_path,
                     const char *export_path, bool keep, char *error, size_t size)
{
    if (size) *error = 0;
    if (!ctx->prepared) { errno = EINVAL; return failure(error, size, "workspace not prepared"); }
    ctx->retained = true;
    int root = pinned_root(ctx), baseline = -1, tree = -1, rc = -1;
    struct manifest before = {.budget = {0, 0, ctx->max_files, ctx->max_bytes}};
    struct manifest after = {.budget = {0, 0, ctx->max_files, ctx->max_bytes}};
    struct change *changes = NULL;
    if (root < 0) return failure(error, size, "private workspace identity changed: %s", strerror(errno));
    baseline = openat(root, "baseline", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    tree = openat(root, "tree", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (baseline < 0 || tree < 0) { failure(error, size, "open completed workspace: %s", strerror(errno)); goto out; }
    if (collect(baseline, baseline, "", 0, &before, error, size) < 0 || collect(tree, tree, "", 0, &after, error, size) < 0) goto out;
    qsort(before.items, before.count, sizeof(*before.items), entry_order);
    qsort(after.items, after.count, sizeof(*after.items), entry_order);
    size_t max_changes = before.count + after.count;
    changes = calloc(max_changes ? max_changes : 1, sizeof(*changes));
    if (!changes) { failure(error, size, "allocate workspace diff: %s", strerror(errno)); goto out; }
    size_t i = 0, j = 0, count = 0;
    while (i < before.count || j < after.count) {
        int order = i == before.count ? 1 : j == after.count ? -1 : strcmp(before.items[i].path, after.items[j].path);
        if (order < 0) changes[count++] = (struct change){&before.items[i++], NULL};
        else if (order > 0) changes[count++] = (struct change){NULL, &after.items[j++]};
        else {
            int same = same_entry(baseline, tree, &before.items[i], &after.items[j]);
            if (same < 0) { failure(error, size, "compare workspace file: %s", strerror(errno)); goto out; }
            if (!same) changes[count++] = (struct change){&before.items[i], &after.items[j]};
            ++i; ++j;
        }
    }
    ctx->changes = count;
    if (export_path) {
        char name[PATH_MAX];
        int parent = output_parent(ctx, export_path, name, sizeof(name), error, size);
        if (parent < 0) goto out;
        if (mkdirat(parent, name, 0700) < 0) { int saved = errno; close(parent); errno = saved; failure(error, size, "create exclusive export: %s", strerror(errno)); goto out; }
        int output = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct budget budget = {0, 0, ctx->max_files, ctx->max_bytes};
        int copied = output >= 0 ? copy_dir(tree, tree, output, "", 0, &budget, error, size) : -1;
        if (copied < 0 && output >= 0) { (void)remove_contents(output, 0); (void)unlinkat(parent, name, AT_REMOVEDIR); }
        if (output >= 0) close(output);
        close(parent);
        if (copied < 0) goto out;
        ctx->exported = true;
    }
    if (diff_path) {
        char name[PATH_MAX];
        int parent = output_parent(ctx, diff_path, name, sizeof(name), error, size);
        if (parent < 0) goto out;
        int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        int saved = errno; close(parent); errno = saved;
        if (fd < 0) { failure(error, size, "create exclusive diff: %s", strerror(errno)); goto out; }
        FILE *f = fdopen(fd, "w");
        if (!f) { close(fd); failure(error, size, "open diff stream: %s", strerror(errno)); goto out; }
        fputs("{\"schema_version\":1,\"source\":", f); json_string(f, ctx->source);
        fputs(",\"workspace\":", f); json_string(f, ctx->tree);
        fprintf(f, ",\"count\":%zu,\"exported\":%s,\"changes\":[", count, ctx->exported ? "true" : "false");
        for (size_t k = 0; k < count; ++k) {
            const struct change *c = &changes[k];
            if (k) fputc(',', f);
            fputs("{\"path\":", f); json_string(f, c->after ? c->after->path : c->before->path);
            fprintf(f, ",\"status\":\"%s\",\"before\":", !c->before ? "added" : !c->after ? "deleted" : "modified");
            json_entry(f, c->before); fputs(",\"after\":", f); json_entry(f, c->after); fputc('}', f);
        }
        fputs("]}\n", f);
        int failed = ferror(f);
        if (fflush(f) < 0 || fsync(fileno(f)) < 0) failed = 1;
        if (fclose(f) < 0) failed = 1;
        if (failed) { failure(error, size, "write workspace diff: %s", strerror(errno)); goto out; }
    }
    rc = 0;
out:;
    int saved = errno;
    free(changes); manifest_free(&before); manifest_free(&after);
    if (baseline >= 0) close(baseline);
    if (tree >= 0) close(tree);
    close(root);
    errno = saved;
    if (rc == 0 && !keep) return workspace_discard(ctx, error, size);
    return rc;
}
