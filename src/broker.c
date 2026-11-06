#define _GNU_SOURCE
#include "broker.h"
#include "network.h"
#include "filebroker.h"
#include "json.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <linux/openat2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

static int errorf(char *out, size_t size, const char *text)
{
    snprintf(out, size, "%s: %s", text, strerror(errno)); return -1;
}

int broker_open(struct config *cfg, char *error, size_t size)
{
    cfg->state = mmap(NULL, sizeof(*cfg->state), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (cfg->state == MAP_FAILED) { cfg->state = NULL; return errorf(error, size, "shared state"); }
    memset(cfg->state, 0, sizeof(*cfg->state));
    cfg->state->audit_fd = -1;
    if (cfg->audit) {
        cfg->state->audit_fd = open(cfg->audit, O_CREAT | O_EXCL | O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (cfg->state->audit_fd < 0) {
            cfg->state->audit_failed = true;
            return errorf(error, size, "create audit");
        }
    }
    return broker_event(cfg, "start", NULL, "", 0, 0);
}

void broker_close(struct config *cfg)
{
    if (!cfg->state) return;
    if (cfg->state->audit_fd >= 0) close(cfg->state->audit_fd);
    munmap(cfg->state, sizeof(*cfg->state)); cfg->state = NULL;
}

int broker_event(const struct config *cfg, const char *kind,
                 const struct seccomp_notif *req, const char *target,
                 long long value, int error)
{
    if (!cfg->state || cfg->state->audit_fd < 0) return 0;
    char *line = NULL; size_t length = 0;
    FILE *f = open_memstream(&line, &length);
    if (!f) { cfg->state->audit_failed = true; return -1; }
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    fputs("{\"schema_version\":1,\"event\":", f); json_string(f, kind);
    fprintf(f, ",\"monotonic_ns\":%llu,\"tid\":%u,\"id\":%llu,\"syscall\":%d,\"arch\":%u,\"target\":",
        (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec,
        req ? req->pid : 0, req ? (unsigned long long)req->id : 0,
        req ? req->data.nr : -1, req ? req->data.arch : 0);
    json_string(f, target ? target : "");
    fputs(",\"target_bytes_hex\":\"", f);
    if (target) for (const unsigned char *p = (const unsigned char *)target; *p; ++p) fprintf(f, "%02x", *p);
    fprintf(f, "\",\"value\":%lld,\"errno\":%d,\"args\":[", value, error);
    for (int i = 0; i < 6; ++i) fprintf(f, "%s%llu", i ? "," : "", req ? (unsigned long long)req->data.args[i] : 0);
    fputs("]}\n", f);
    int failed = ferror(f);
    if (fclose(f) != 0) failed = 1;
    if (failed) { free(line); cfg->state->audit_failed = true; return -1; }
    unsigned long long reserved = atomic_fetch_add(&cfg->state->audit_reserved_bytes, length);
    unsigned long long records = atomic_fetch_add(&cfg->state->audit_reserved_records, 1);
    if (reserved > cfg->audit_max_bytes || length > cfg->audit_max_bytes - reserved || records >= cfg->audit_max_records) {
        free(line); cfg->state->audit_limit_exceeded = true; cfg->state->audit_failed = true;
        errno = EFBIG; return -1;
    }
    ssize_t written;
    do { written = write(cfg->state->audit_fd, line, length); } while (written < 0 && errno == EINTR);
    free(line);
    if (written != (ssize_t)length) { cfg->state->audit_failed = true; return -1; }
    ++cfg->state->audit_records; cfg->state->audit_bytes += length;
    if (!strcmp(kind, "finish")) cfg->state->audit_finished = true;
    return 0;
}

static int network_audit(const struct seccomp_notif *req, const char *phase,
                         const char *target, long long value, int error, void *context)
{
    const struct config *cfg = context;
    int result = broker_event(cfg, phase, req, target, value, error);
    if (cfg->audit && cfg->state) {
        if (!strcmp(phase, "delivery_begin") && result == 0) ++cfg->state->delivery_pending;
        if (!strcmp(phase, "delivery_end")) --cfg->state->delivery_pending;
        if (!strcmp(phase, "delivery_end") && error) cfg->state->audit_failed = true;
    }
    return result;
}

int broker_send_listener(int transport, int listener)
{
    char byte = 'L'; struct iovec iov = {&byte, 1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &listener, sizeof(listener));
    ssize_t sent;
    do { sent = sendmsg(transport, &msg, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    return sent == 1 ? 0 : -1;
}

/* recvmsg may leave the caller's control length untouched on failure. Parse
 * only successful replies and never trust an ancillary length beyond the
 * buffer actually returned by the kernel. Close every extra installed FD. */
static int receive_rights(const struct msghdr *msg, size_t capacity,
                          int *selected, size_t *count)
{
    *selected = -1; *count = 0;
    if (msg->msg_controllen > capacity) { errno = EPROTO; return -1; }
    size_t offset = 0;
    bool unexpected = false;
    while (msg->msg_controllen - offset >= sizeof(struct cmsghdr)) {
        const unsigned char *bytes = (const unsigned char *)msg->msg_control + offset;
        struct cmsghdr header;
        memcpy(&header, bytes, sizeof(header));
        size_t remaining = msg->msg_controllen - offset;
        if (header.cmsg_len < CMSG_LEN(0) || header.cmsg_len > remaining) {
            errno = EPROTO; return -1;
        }
        size_t length = header.cmsg_len - CMSG_LEN(0);
        if (header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS) {
            if (length % sizeof(int)) unexpected = true;
            for (size_t i = 0; i < length / sizeof(int); ++i) {
                int fd; memcpy(&fd, bytes + CMSG_LEN(0) + i * sizeof(int), sizeof(fd));
                if (!*count) *selected = fd; else close(fd);
                ++*count;
            }
        } else unexpected = true;
        /* A final record need not include its trailing alignment padding. */
        size_t step = CMSG_ALIGN(header.cmsg_len);
        if (step > remaining) break;
        offset += step;
    }
    if (unexpected) { errno = EPROTO; return -1; }
    return 0;
}

int broker_receive_listener(int transport)
{
    char byte = 0; struct iovec iov = {&byte, 1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int) * 8)]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    ssize_t n = recvmsg(transport, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return -2;
    if (n < 0) return -1;
    int selected = -1; size_t count = 0;
    int ancillary = receive_rights(&msg, sizeof(control.bytes), &selected, &count);
    if (ancillary < 0 || n != 1 || byte != 'L' || count != 1 || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        if (selected >= 0) close(selected);
        errno = EPROTO; return -1;
    }
    if (fcntl(selected, F_SETFL, O_NONBLOCK) < 0) { close(selected); return -1; }
    return selected;
}

struct memory_request { uint64_t id; uint32_t pid; uint32_t writable; };
static int memory_transport = -1;

int broker_memory_open(int listener, const struct seccomp_notif *request, bool writable)
{
    if (memory_transport < 0) { errno = EPROTO; return -1; }
    uint64_t id = request->id;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) return -1;
    struct memory_request query = {.id = id, .pid = request->pid, .writable = writable};
    ssize_t sent;
    do { sent = send(memory_transport, &query, sizeof(query), MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    if (sent != sizeof(query)) return -1;
    int error = EPROTO;
    struct iovec iov = {&error, sizeof(error)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(8 * sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr reply = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)};
    ssize_t n;
    do { n = recvmsg(memory_transport, &reply, MSG_CMSG_CLOEXEC); } while (n < 0 && errno == EINTR);
    if (n < 0) return -1;
    int selected = -1; size_t count = 0;
    int ancillary = receive_rights(&reply, sizeof(control.bytes), &selected, &count);
    if (ancillary < 0 || n != sizeof(error) || (reply.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        (error ? count != 0 : count != 1)) {
        if (selected >= 0) close(selected);
        errno = EPROTO; return -1;
    }
    if (error) { errno = error; return -1; }
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) { close(selected); return -1; }
    return selected;
}

int broker_service_memory(int channel, int listener)
{
    struct memory_request query;
    ssize_t n = recv(channel, &query, sizeof(query), MSG_DONTWAIT);
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) return 0;
    if (n != sizeof(query) || !query.pid || query.writable > 1) { errno = EPROTO; return -1; }
    int fd = -1, error = 0;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &query.id) < 0) error = errno;
    if (!error) {
        char path[96]; snprintf(path, sizeof(path), "/proc/%u/mem", query.pid);
        fd = open(path, (query.writable ? O_RDWR : O_RDONLY) | O_CLOEXEC);
        if (fd < 0) error = errno;
        else if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &query.id) < 0) {
            error = errno; close(fd); fd = -1;
        }
    }
    struct iovec iov = {&error, sizeof(error)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr reply = {.msg_iov = &iov, .msg_iovlen = 1};
    if (fd >= 0) {
        reply.msg_control = control.bytes; reply.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *c = CMSG_FIRSTHDR(&reply); c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof(fd));
    }
    ssize_t sent;
    do { sent = sendmsg(channel, &reply, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    if (fd >= 0) close(fd);
    return sent == sizeof(error) ? 0 : -1;
}

static int remote_read(int listener, const struct seccomp_notif *r,
                        uint64_t address, void *out, size_t size)
{
    if (!address || address > (uint64_t)LLONG_MAX || size > (uint64_t)LLONG_MAX - address) { errno = EFAULT; return -1; }
    int fd = broker_memory_open(listener, r, false);
    if (fd < 0) return -1;
    uint64_t id = r->id;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) { close(fd); return -1; }
    ssize_t n = pread(fd, out, size, (off_t)address); int saved = errno; close(fd);
    if (n != (ssize_t)size) { errno = n < 0 ? saved : EFAULT; return -1; }
    return ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id);
}

static int remote_string(int listener, const struct seccomp_notif *r, uint64_t address, char *out, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (remote_read(listener, r, address + i, out + i, 1) < 0) return -1;
        if (!out[i]) return 0;
    }
    errno = ENAMETOOLONG; return -1;
}

static int path_from_fd(const struct seccomp_notif *r, int fd, bool cwd, char *out, size_t size)
{
    if (!size) { errno = ENAMETOOLONG; return -1; }
    char proc[96];
    if (cwd) snprintf(proc, sizeof(proc), "/proc/%u/cwd", r->pid);
    else snprintf(proc, sizeof(proc), "/proc/%u/fd/%d", r->pid, fd);
    /* readlink does not append NUL. Read the full buffer so a valid
     * PATH_MAX-1 target fits, and distinguish a full/truncated reply from an
     * actual readlink error. Never propagate success with a stale errno. */
    ssize_t n = readlink(proc, out, size);
    if (n < 0) return -1;
    if ((size_t)n >= size) { errno = ENAMETOOLONG; return -1; }
    out[n] = 0; return 0;
}

static int metadata_object(const struct config *cfg, int listener, const struct seccomp_notif *r,
                            int dirfd, uint64_t pointer, bool by_fd, char *target, size_t size)
{
    char user[PATH_MAX], base[PATH_MAX];
    if (by_fd) {
        if (path_from_fd(r, dirfd, false, target, size) < 0) return -1;
    } else {
        if (remote_string(listener, r, pointer, user, sizeof(user)) < 0) return -1;
        if (user[0] == '/') snprintf(target, size, "%s", user);
        else {
            if (path_from_fd(r, dirfd, dirfd == AT_FDCWD, base, sizeof(base)) < 0) return -1;
            if (snprintf(target, size, "%s/%s", base, user) >= (int)size) { errno = ENAMETOOLONG; return -1; }
        }
    }
    uint64_t id = r->id;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) return -1;
    for (size_t i = 0; i < cfg->rule_count; ++i) {
        if (cfg->rules[i].mode != PATH_RW) continue;
        const char *root = cfg->rule_targets[i];
        if (!cfg->policy_pinned || !root) continue;
        size_t length = strlen(root);
        if (strncmp(root, target, length) || (length > 1 && target[length] && target[length] != '/')) continue;
        int parent = fcntl(cfg->rule_fds[i], F_DUPFD_CLOEXEC, 3);
        if (parent < 0) continue;
        struct stat st; if (fstat(parent, &st) < 0) { close(parent); continue; }
        int object = -1;
        if (!target[length]) object = parent;
        else if (S_ISDIR(st.st_mode)) {
            const char *relative = target + length;
            while (*relative == '/') ++relative;
            struct open_how how = {.flags = O_PATH | O_CLOEXEC,
                .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS};
            object = (int)syscall(SYS_openat2, parent, relative, &how, sizeof(how)); close(parent);
        } else close(parent);
        if (object < 0) continue;
        if (fstat(object, &st) < 0 || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) { close(object); continue; }
        if (by_fd) {
            char proc[96]; struct stat original;
            snprintf(proc, sizeof(proc), "/proc/%u/fd/%d", r->pid, dirfd);
            if (stat(proc, &original) < 0 || original.st_dev != st.st_dev || original.st_ino != st.st_ino) { close(object); continue; }
        }
        if (st.st_uid != geteuid() || ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) { close(object); continue; }
        return object;
    }
    errno = EACCES; return -1;
}

static int metadata_handle(const struct config *cfg, int listener, const struct seccomp_notif *r,
                            struct seccomp_notif_resp *response)
{
    int nr = r->data.nr, dirfd = AT_FDCWD, operation = 0;
    uint64_t path = r->data.args[0], extra = 0, extra2 = 0;
    bool by_fd = false;
    switch (nr) {
#ifdef SYS_chmod
    case SYS_chmod: operation = 1; extra = r->data.args[1]; break;
#endif
    case SYS_fchmod: operation = 1; by_fd = true; dirfd = (int)r->data.args[0]; extra = r->data.args[1]; break;
    case SYS_fchmodat: case 452:
        if (nr == 452 && r->data.args[3] != 0) { response->error = -EOPNOTSUPP; return 0; }
        operation = 1; dirfd = (int)r->data.args[0]; path = r->data.args[1]; extra = r->data.args[2]; break;
#ifdef SYS_chown
    case SYS_chown: case SYS_lchown: operation = 2; extra = r->data.args[1]; extra2 = r->data.args[2]; break;
#endif
    case SYS_fchown: operation = 2; by_fd = true; dirfd = (int)r->data.args[0]; extra = r->data.args[1]; extra2 = r->data.args[2]; break;
    case SYS_fchownat:
        if (r->data.args[4] != 0) { response->error = -EOPNOTSUPP; return 0; }
        operation = 2; dirfd = (int)r->data.args[0]; path = r->data.args[1]; extra = r->data.args[2]; extra2 = r->data.args[3]; break;
    case SYS_utimensat:
        if (r->data.args[3] != 0) { response->error = -EOPNOTSUPP; return 0; }
        operation = 3; dirfd = (int)r->data.args[0]; path = r->data.args[1]; extra = r->data.args[2]; break;
    case SYS_setxattr: case SYS_lsetxattr: operation = 4; break;
    case SYS_fsetxattr: operation = 4; by_fd = true; dirfd = (int)r->data.args[0]; break;
    case SYS_removexattr: case SYS_lremovexattr: operation = 5; break;
    case SYS_fremovexattr: operation = 5; by_fd = true; dirfd = (int)r->data.args[0]; break;
    default: response->error = -EOPNOTSUPP; return 0;
    }
    char target[PATH_MAX];
    int object = metadata_object(cfg, listener, r, dirfd, path, by_fd, target, sizeof(target));
    if (object < 0) { response->error = -(errno ? errno : EIO); return 0; }
    if (broker_event(cfg, "authorize", r, target, 0, 0) < 0) { close(object); return -1; }
    if (cfg->audit && cfg->state) ++cfg->state->delivery_pending;
    int result = -1;
    if (operation == 1) {
        if (extra & ~0777ULL) errno = EPERM;
        else result = (int)syscall(452, object, "", (mode_t)extra, AT_EMPTY_PATH);
    } else if (operation == 2) {
        if (((uid_t)extra != (uid_t)-1 && (uid_t)extra != geteuid()) ||
            ((gid_t)extra2 != (gid_t)-1 && (gid_t)extra2 != getegid())) errno = EPERM;
        else result = fchownat(object, "", (uid_t)extra, (gid_t)extra2, AT_EMPTY_PATH);
    } else if (operation == 3) {
        struct timespec times[2];
        if (extra && remote_read(listener, r, extra, times, sizeof(times)) < 0) result = -1;
        else result = (int)syscall(SYS_utimensat, object, "", extra ? times : NULL, AT_EMPTY_PATH);
    } else {
        char name[256], proc[80];
        snprintf(proc, sizeof(proc), "/proc/self/fd/%d", object);
        if (remote_string(listener, r, r->data.args[1], name, sizeof(name)) < 0) result = -1;
        else if (strncmp(name, "user.", 5)) errno = EPERM;
        else if (operation == 5) result = removexattr(proc, name);
        else if (r->data.args[3] > 65536) errno = E2BIG;
        else {
            size_t length = (size_t)r->data.args[3];
            void *value = malloc(length ? length : 1);
            if (!value) result = -1;
            else {
                if (length && remote_read(listener, r, r->data.args[2], value, length) < 0) result = -1;
                else result = setxattr(proc, name, value, length, (int)r->data.args[4]);
                free(value);
            }
        }
    }
    int saved = result < 0 ? (errno ? errno : EIO) : 0; close(object);
    response->error = -saved; response->val = result < 0 ? 0 : result;
    int recorded = broker_event(cfg, "result", r, target, response->val, saved);
    if (cfg->audit && cfg->state) --cfg->state->delivery_pending;
    if (recorded < 0) return -1;
    return 0;
}

int broker_drain(const struct config *cfg, int listener, int abi)
{
    if (cfg->network) network_observe(cfg->network, network_audit, (void *)cfg);
    for (int batch = 0; batch < 32; ++batch) {
        struct pollfd pending = {.fd = listener, .events = POLLIN};
        if (poll(&pending, 1, 0) <= 0 || !(pending.revents & POLLIN)) return 0;
        struct seccomp_notif request = {0};
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) < 0) {
            if (errno == EAGAIN || errno == ENOENT || errno == EINTR) return 0;
            return -1;
        }
        ++cfg->state->requests;
        struct seccomp_notif_resp response = {.id = request.id};
        if (broker_event(cfg, "request", &request, "", 0, 0) < 0) return -1;
        if (cfg->audit_syscalls) {
            int opened = filebroker_handle(cfg, listener, &request, &response);
            if (opened == -1) return -1;
            if (opened >= 0) {
                ++cfg->state->brokered;
                if (opened == 1) continue;
                if (broker_event(cfg, "file_open_denied", &request, "", 0, -response.error) < 0) return -1;
                if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) < 0 && errno != ENOENT) return -1;
                continue;
            }
        }
        uint32_t decision = security_decide(cfg, abi, &request.data);
        uint32_t action = decision & SECCOMP_RET_ACTION_FULL;
        if (action == SECCOMP_RET_ERRNO) { response.error = -(int)(decision & SECCOMP_RET_DATA); ++cfg->state->denied; }
        else if (action == SECCOMP_RET_ALLOW) {
            response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; ++cfg->state->continued;
        } else if (action == SECCOMP_RET_USER_NOTIF) {
            int handled = cfg->network ? network_handle(cfg->network, listener, &request, &response) : -2;
            if (handled == -2 && cfg->metadata) handled = metadata_handle(cfg, listener, &request, &response);
            if (handled == -1) return -1;
            if (handled == -2) response.error = -EPERM;
            ++cfg->state->brokered;
            if (handled == 1) continue;
        } else response.error = -EPERM;
        const char *event = response.flags ? "continue_request" : (response.error ? "deny" : "response");
        if (broker_event(cfg, event, &request, "", response.val, -response.error) < 0) return -1;
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) < 0 && errno != ENOENT) return -1;
    }
    return 0;
}

int broker_run(const struct config *cfg, int listener, int abi, pid_t payload_group, int memory_channel)
{
    memory_transport = memory_channel;
    if (cfg->caller_fd >= 0) close(cfg->caller_fd);
    if (security_drop_capabilities() < 0) return 125;
    for (;;) {
        if (cfg->state && cfg->state->audit_failed) return 125;
        struct pollfd p = {.fd = listener, .events = POLLIN};
        int ready = poll(&p, 1, 50);
        if (ready < 0 && errno != EINTR) return 125;
        if (ready > 0 && (p.revents & POLLIN) && broker_drain(cfg, listener, abi) < 0) return 125;
        if (p.revents & POLLHUP) {
            /* Last filtered task may be finishing its kernel exit before its
             * pidfd is readable. Stay alive for the monitor to reap/kill us;
             * a normal listener HUP is not a broker crash. */
            for (;;) poll(NULL, 0, -1);
        }
        if (p.revents & (POLLERR | POLLNVAL)) return 125;
        if (cfg->network && network_gc(cfg->network, payload_group) < 0 && cfg->state) ++cfg->state->gc_deferred;
        filebroker_reap();
    }
}
