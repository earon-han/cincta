#define _GNU_SOURCE
#include "network.h"
#include "broker.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define NET_MAX_ENDPOINTS 1024
#define NET_MAX_MESSAGE (1024U * 1024U)
#define NET_MAX_IOV 64

struct endpoint {
    int family;
    int protocol;
    unsigned prefix;
    unsigned short port_first, port_last;
    unsigned char address[16];
    char source[320];
};
struct owned_socket {
    int fd;
    int family, type, protocol;
    ino_t inode;
    dev_t device;
};
struct net_policy {
    struct endpoint endpoints[NET_MAX_ENDPOINTS];
    size_t endpoint_count;
    struct owned_socket sockets[CINCTA_NET_MAX_SOCKETS];
    pid_t workers[CINCTA_NET_MAX_WORKERS];
    network_observer observer;
    void *observer_context;
};

void network_observe(struct net_policy *p, network_observer observer, void *context)
{
    if (p) { p->observer = observer; p->observer_context = context; }
}

static int observe(struct net_policy *p, const struct seccomp_notif *request,
                    const char *phase, const char *target, long long value, int error)
{
    return p->observer ? p->observer(request, phase, target, value, error, p->observer_context) : 0;
}

static void describe_target(const struct sockaddr_storage *address, int protocol,
                             char *target, size_t size)
{
    char ip[INET6_ADDRSTRLEN];
    unsigned port;
    if (address->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)address;
        inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip)); port = ntohs(a->sin_port);
        snprintf(target, size, "%s:%s:%u", protocol == IPPROTO_TCP ? "tcp" : "udp", ip, port);
    } else {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)address;
        inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip)); port = ntohs(a->sin6_port);
        snprintf(target, size, "%s:[%s]:%u", protocol == IPPROTO_TCP ? "tcp" : "udp", ip, port);
    }
}

static int errorf(char *out, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (size) vsnprintf(out, size, format, args);
    va_end(args);
    errno = EINVAL;
    return -1;
}

static int parse_unsigned(const char *text, unsigned maximum, unsigned *out)
{
    char *end;
    if (!text || !*text || *text < '0' || *text > '9') return -1;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || *end || value > maximum) return -1;
    *out = (unsigned)value;
    return 0;
}

static int add_endpoint(struct net_policy *p, const char *source, int family,
                        int protocol, const void *address, unsigned prefix,
                        unsigned first, unsigned last)
{
    if (p->endpoint_count == NET_MAX_ENDPOINTS) return -1;
    struct endpoint *e = &p->endpoints[p->endpoint_count++];
    *e = (struct endpoint){ .family = family, .protocol = protocol,
        .prefix = prefix, .port_first = (unsigned short)first,
        .port_last = (unsigned short)last };
    memcpy(e->address, address, family == AF_INET ? 4 : 16);
    snprintf(e->source, sizeof(e->source), "%s", source);
    return 0;
}

int network_prepare(const char *const *rules, size_t count,
                    struct net_policy **out, char *error, size_t size)
{
    *out = NULL;
    if (!count || count > CINCTA_NET_MAX_RULES)
        return errorf(error, size, "network policy needs 1..%d rules", CINCTA_NET_MAX_RULES);
    struct net_policy *p = calloc(1, sizeof(*p));
    if (!p) return -1;
    for (size_t i = 0; i < CINCTA_NET_MAX_SOCKETS; ++i) p->sockets[i].fd = -1;
    for (size_t i = 0; i < count; ++i) {
        char text[320];
        if (!rules[i] || strlen(rules[i]) >= sizeof(text)) {
            network_destroy(p); return errorf(error, size, "network rule is too long");
        }
        strcpy(text, rules[i]);
        char *host = strchr(text, ':');
        if (!host) { network_destroy(p); return errorf(error, size, "expected tcp:host:port or udp:host:port"); }
        *host++ = '\0';
        int protocol = !strcmp(text, "tcp") ? IPPROTO_TCP : !strcmp(text, "udp") ? IPPROTO_UDP : 0;
        if (!protocol) { network_destroy(p); return errorf(error, size, "network protocol must be tcp or udp"); }
        char *ports;
        if (*host == '[') {
            ++host;
            ports = strchr(host, ']');
            if (!ports || ports[1] != ':') {
                network_destroy(p); return errorf(error, size, "IPv6 rules must use [address/prefix]:port");
            }
            *ports = '\0'; ports += 2;
        } else {
            ports = strchr(host, ':');
            if (!ports || strchr(ports + 1, ':')) {
                network_destroy(p); return errorf(error, size, "expected host:port; bracket IPv6 literals");
            }
            *ports++ = '\0';
        }
        char *dash = strchr(ports, '-');
        unsigned first, last;
        if (dash) *dash++ = '\0';
        if (parse_unsigned(ports, 65535, &first) || !first ||
            (dash && parse_unsigned(dash, 65535, &last))) {
            network_destroy(p); return errorf(error, size, "invalid network port or port range");
        }
        if (!dash) last = first;
        if (last < first) { network_destroy(p); return errorf(error, size, "reversed port range"); }
        char *slash = strchr(host, '/');
        unsigned prefix = 0;
        if (slash) *slash++ = '\0';
        unsigned char address[16];
        int family = inet_pton(AF_INET, host, address) == 1 ? AF_INET :
                     inet_pton(AF_INET6, host, address) == 1 ? AF_INET6 : 0;
        if (family) {
            unsigned maximum = family == AF_INET ? 32 : 128;
            prefix = maximum;
            if (slash && parse_unsigned(slash, maximum, &prefix)) {
                network_destroy(p); return errorf(error, size, "invalid CIDR prefix");
            }
            if (add_endpoint(p, rules[i], family, protocol, address, prefix, first, last)) {
                network_destroy(p); return errorf(error, size, "too many resolved network addresses");
            }
        } else {
            if (slash || !*host) {
                network_destroy(p); return errorf(error, size, "CIDR requires a numeric IP address");
            }
            /* Strict hostname grammar avoids resolver-specific numeric syntax,
             * scoped IPv6, wildcard names and accidentally accepted URLs. */
            for (const unsigned char *c = (const unsigned char *)host; *c; ++c) {
                if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
                      (*c >= '0' && *c <= '9') || *c == '.' || *c == '-')) {
                    network_destroy(p); return errorf(error, size, "invalid domain name");
                }
            }
            struct addrinfo hints = {.ai_family = AF_UNSPEC,
                .ai_socktype = protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM};
            struct addrinfo *addresses = NULL;
            struct addrinfo numeric_hints = hints;
            numeric_hints.ai_flags = AI_NUMERICHOST;
            struct addrinfo *numeric = NULL;
            if (getaddrinfo(host, NULL, &numeric_hints, &numeric) == 0) {
                freeaddrinfo(numeric); network_destroy(p);
                return errorf(error, size, "numeric IP address must use canonical notation");
            }
            int rc = getaddrinfo(host, NULL, &hints, &addresses);
            if (rc || !addresses) {
                network_destroy(p); return errorf(error, size, "resolve '%s': %s", host, gai_strerror(rc));
            }
            for (struct addrinfo *a = addresses; a; a = a->ai_next) {
                const void *bytes = NULL;
                if (a->ai_family == AF_INET)
                    bytes = &((struct sockaddr_in *)a->ai_addr)->sin_addr;
                else if (a->ai_family == AF_INET6)
                    bytes = &((struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
                if (bytes && add_endpoint(p, rules[i], a->ai_family, protocol, bytes,
                    a->ai_family == AF_INET ? 32 : 128, first, last)) {
                    freeaddrinfo(addresses); network_destroy(p);
                    return errorf(error, size, "too many resolved network addresses");
                }
            }
            freeaddrinfo(addresses);
        }
    }
    *out = p;
    return 0;
}

static int valid_id(int listener, uint64_t id)
{
    return ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id);
}

static int memory_open(int listener, const struct seccomp_notif *request)
{
    /* The real ancestor monitor opens and validates this mm over a private
     * RPC channel. A sibling broker's Yama exception does not inherit across
     * payload forks, so it must not reopen /proc/TID/mem by itself. */
    return broker_memory_open(listener, request, false);
}

static int memory_read(int fd, uint64_t pointer, void *buffer, size_t length)
{
    if (pointer > INT64_MAX || length > INT64_MAX - pointer) { errno = EFAULT; return -1; }
    ssize_t n;
    do { n = pread(fd, buffer, length, (off_t)pointer); } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)length) { errno = EFAULT; return -1; }
    return 0;
}

static struct owned_socket *lookup_socket(struct net_policy *p, int listener,
                                          const struct seccomp_notif *r, uint64_t number)
{
    if (number > INT_MAX) { errno = EBADF; return NULL; }
    char path[80];
    snprintf(path, sizeof(path), "/proc/%u/fd/%u", r->pid, (unsigned)number);
    /* Pin the object, then validate the request. Socket inode text alone is
     * not an identity: compare the sockfs device, inode and inode type. */
    int target = open(path, O_PATH | O_CLOEXEC);
    if (target < 0) return NULL;
    struct stat st;
    int rc = valid_id(listener, r->id);
    if (rc == 0) rc = fstat(target, &st);
    int saved = errno;
    close(target);
    if (rc < 0) { errno = saved; return NULL; }
    if (!S_ISSOCK(st.st_mode)) { errno = ENOTSOCK; return NULL; }
    for (size_t i = 0; i < CINCTA_NET_MAX_SOCKETS; ++i)
        if (p->sockets[i].fd >= 0 && p->sockets[i].inode == st.st_ino && p->sockets[i].device == st.st_dev)
            return &p->sockets[i];
    errno = EPERM;
    return NULL;
}

static bool prefix_matches(const unsigned char *left, const unsigned char *right, unsigned bits)
{
    unsigned bytes = bits / 8, rest = bits % 8;
    return !memcmp(left, right, bytes) && (!rest ||
        ((left[bytes] ^ right[bytes]) & (unsigned char)(0xffU << (8 - rest))) == 0);
}

static bool address_allowed(const struct net_policy *p, int protocol,
                            const struct sockaddr_storage *address)
{
    const unsigned char *bytes;
    unsigned port;
    int family = address->ss_family;
    if (family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)address;
        bytes = (const unsigned char *)&v4->sin_addr; port = ntohs(v4->sin_port);
    } else if (family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)address;
        bytes = (const unsigned char *)&v6->sin6_addr; port = ntohs(v6->sin6_port);
        if (v6->sin6_scope_id != 0) return false;
    } else return false;
    for (size_t i = 0; i < p->endpoint_count; ++i) {
        const struct endpoint *e = &p->endpoints[i];
        if (e->protocol != protocol || port < e->port_first || port > e->port_last) continue;
        if (e->family == family && prefix_matches(e->address, bytes, e->prefix)) return true;
        if (family == AF_INET6 && e->family == AF_INET &&
            IN6_IS_ADDR_V4MAPPED(&((const struct sockaddr_in6 *)address)->sin6_addr) &&
            prefix_matches(e->address, bytes + 12, e->prefix)) return true;
    }
    return false;
}

static int copy_address(int memory, uint64_t pointer, uint64_t length,
                        struct sockaddr_storage *out, socklen_t *out_size)
{
    memset(out, 0, sizeof(*out));
    if (!pointer || length > sizeof(*out) || length < sizeof(sa_family_t)) { errno = EINVAL; return -1; }
    if (memory_read(memory, pointer, out, (size_t)length) < 0) return -1;
    socklen_t expected = out->ss_family == AF_INET ? sizeof(struct sockaddr_in) :
                         out->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : 0;
    if (!expected || length < expected) { errno = EAFNOSUPPORT; return -1; }
    *out_size = expected;
    return 0;
}

static void fill_response(struct seccomp_notif_resp *response, uint64_t id,
                          long value, int error)
{
    *response = (struct seccomp_notif_resp){ .id = id, .val = value, .error = -error };
}

static int send_response(int listener, const struct seccomp_notif_resp *response)
{
    int rc;
    do { rc = ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response); } while (rc < 0 && errno == EINTR);
    return rc < 0 && errno != ENOENT ? -1 : 0;
}

static void reap_workers(struct net_policy *p)
{
    for (size_t i = 0; i < CINCTA_NET_MAX_WORKERS; ++i) {
        if (p->workers[i] <= 0) continue;
        int status;
        pid_t got = waitpid(p->workers[i], &status, WNOHANG);
        if (got == p->workers[i] || (got < 0 && errno == ECHILD)) p->workers[i] = 0;
    }
}

static pid_t start_worker(struct net_policy *p)
{
    reap_workers(p);
    for (size_t i = 0; i < CINCTA_NET_MAX_WORKERS; ++i) {
        if (p->workers[i]) continue;
        pid_t child = fork();
        if (child > 0) p->workers[i] = child;
        return child;
    }
    errno = EAGAIN;
    return -1;
}

static void worker_close_other_sockets(struct net_policy *p, int keep)
{
    /* A slow connection must not keep unrelated TCP connections alive merely
     * because fork inherited the broker registry. Audit/control FDs belong to
     * the trusted monitor callback and are deliberately not guessed here. */
    for (size_t i = 0; i < CINCTA_NET_MAX_SOCKETS; ++i)
        if (p->sockets[i].fd >= 0 && p->sockets[i].fd != keep) close(p->sockets[i].fd);
}

static int handle_socket(struct net_policy *p, int listener,
                          const struct seccomp_notif *r, struct seccomp_notif_resp *response)
{
    int family = (int)r->data.args[0], type = (int)r->data.args[1];
    int base_type = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK), protocol = (int)r->data.args[2];
    if ((family != AF_INET && family != AF_INET6) ||
        (base_type != SOCK_STREAM && base_type != SOCK_DGRAM) ||
        (protocol != 0 && protocol != (base_type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP))) {
        fill_response(response, r->id, 0, EPERM); return 0;
    }
    size_t slot;
    for (slot = 0; slot < CINCTA_NET_MAX_SOCKETS; ++slot) if (p->sockets[slot].fd < 0) break;
    if (slot == CINCTA_NET_MAX_SOCKETS) { fill_response(response, r->id, 0, EMFILE); return 0; }
    int fd = socket(family, type | SOCK_CLOEXEC, protocol);
    if (fd < 0) { fill_response(response, r->id, 0, errno); return 0; }
    struct stat st;
    if (fstat(fd, &st) < 0) { int error = errno; close(fd); fill_response(response, r->id, 0, error); return 0; }
    struct seccomp_notif_addfd add = { .id = r->id, .flags = SECCOMP_ADDFD_FLAG_SEND,
        .srcfd = (unsigned)fd, .newfd_flags = type & SOCK_CLOEXEC ? O_CLOEXEC : 0 };
    if (observe(p, r, "authorize", "", 0, 0) < 0) {
        close(fd); fill_response(response, r->id, 0, EIO); return 0;
    }
    if (observe(p, r, "delivery_begin", "", 0, 0) < 0) {
        close(fd); fill_response(response, r->id, 0, EIO); return 0;
    }
    int injected = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
    if (injected < 0) {
        int error = errno; close(fd);
        int logged = observe(p, r, "result", "", 0, error);
        int ended = observe(p, r, "delivery_end", "", 0, 0);
        if (error == ENOENT) return 1;
        fill_response(response, r->id, 0, logged < 0 || ended < 0 ? EIO : error); return 0;
    }
    p->sockets[slot] = (struct owned_socket){ .fd = fd, .family = family, .type = base_type,
        .protocol = base_type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP,
        .inode = st.st_ino, .device = st.st_dev };
    (void)observe(p, r, "result", "", injected, 0);
    (void)observe(p, r, "delivery_end", "", injected, 0);
    return 1;
}

static int handle_connect(struct net_policy *p, int listener, const struct seccomp_notif *r,
                           struct seccomp_notif_resp *response)
{
    struct owned_socket *s = lookup_socket(p, listener, r, r->data.args[0]);
    if (!s) { fill_response(response, r->id, 0, errno); return 0; }
    int memory = memory_open(listener, r);
    if (memory < 0) { fill_response(response, r->id, 0, errno); return 0; }
    struct sockaddr_storage address;
    socklen_t size;
    int rc = copy_address(memory, r->data.args[1], r->data.args[2], &address, &size);
    int error = errno;
    close(memory);
    if (rc < 0) { fill_response(response, r->id, 0, error); return 0; }
    if (!address_allowed(p, s->protocol, &address)) { fill_response(response, r->id, 0, EACCES); return 0; }
    if (valid_id(listener, r->id) < 0) return 1;
    char target[96];
    describe_target(&address, s->protocol, target, sizeof(target));
    if (observe(p, r, "authorize", target, 0, 0) < 0) { fill_response(response, r->id, 0, EIO); return 0; }
    if (observe(p, r, "delivery_begin", target, 0, 0) < 0) { fill_response(response, r->id, 0, EIO); return 0; }
    pid_t worker = start_worker(p);
    if (worker < 0) {
        int saved = errno;
        int logged = observe(p, r, "result", target, -1, saved);
        int ended = observe(p, r, "delivery_end", target, 0, 0);
        fill_response(response, r->id, 0, logged < 0 || ended < 0 ? EIO : saved); return 0;
    }
    if (worker == 0) {
        worker_close_other_sockets(p, s->fd);
        int delivery_error = 0;
        if (valid_id(listener, r->id) == 0) {
            int result = connect(s->fd, (struct sockaddr *)&address, size);
            int saved = result < 0 ? errno : 0;
            if (observe(p, r, "result", target, result, saved) < 0) saved = EIO;
            fill_response(response, r->id, result < 0 ? 0 : result, saved);
            if (send_response(listener, response) < 0) delivery_error = errno;
        } else {
            (void)observe(p, r, "result", target, -1, ECANCELED);
        }
        (void)observe(p, r, "delivery_end", target, 0, delivery_error);
        _exit(0);
    }
    return 1;
}

static int handle_send(struct net_policy *p, int listener, const struct seccomp_notif *r,
                        struct seccomp_notif_resp *response, bool message)
{
    struct owned_socket *s = lookup_socket(p, listener, r, r->data.args[0]);
    if (!s) { fill_response(response, r->id, 0, errno); return 0; }
    int memory = memory_open(listener, r);
    if (memory < 0) { fill_response(response, r->id, 0, errno); return 0; }
    struct sockaddr_storage address;
    socklen_t address_size = 0;
    uint64_t pointer = r->data.args[1], length = r->data.args[2];
    uint64_t address_pointer = r->data.args[4], address_length = r->data.args[5];
    int flags = (int)r->data.args[3];
    struct msghdr header = {0};
    struct iovec vectors[NET_MAX_IOV];
    int error = 0;
    if (message) {
        flags = (int)r->data.args[2];
        if (memory_read(memory, pointer, &header, sizeof(header)) < 0) { error = errno; goto failed; }
        if (header.msg_controllen || header.msg_iovlen > NET_MAX_IOV) { error = EOPNOTSUPP; goto failed; }
        address_pointer = (uintptr_t)header.msg_name; address_length = header.msg_namelen;
        if (memory_read(memory, (uintptr_t)header.msg_iov, vectors,
                        header.msg_iovlen * sizeof(struct iovec)) < 0) { error = errno; goto failed; }
        length = 0;
        for (size_t i = 0; i < header.msg_iovlen; ++i) {
            if (vectors[i].iov_len > NET_MAX_MESSAGE - length) { error = EMSGSIZE; goto failed; }
            length += vectors[i].iov_len;
        }
    }
    if (length > NET_MAX_MESSAGE) { error = EMSGSIZE; goto failed; }
    if (address_pointer) {
        if (copy_address(memory, address_pointer, address_length, &address, &address_size) < 0) {
            error = errno; goto failed;
        }
        if (!address_allowed(p, s->protocol, &address)) { error = EACCES; goto failed; }
    } else {
        /* A connected peer can only have been established by handle_connect.
         * Check the retained socket's current peer as well, including races
         * between approved reconnect requests from different target threads. */
        socklen_t peer_size = sizeof(address);
        if (getpeername(s->fd, (struct sockaddr *)&address, &peer_size) < 0) { error = errno; goto failed; }
        if (!address_allowed(p, s->protocol, &address)) { error = EACCES; goto failed; }
        /* Freeze a connected UDP peer for this effect; another thread can
         * reconnect the shared socket after our policy/audit snapshot. */
        if (s->protocol == IPPROTO_UDP) address_size = peer_size;
    }
    unsigned char *data = malloc(length ? (size_t)length : 1);
    if (!data) { error = ENOMEM; goto failed; }
    if (message) {
        size_t offset = 0;
        for (size_t i = 0; i < header.msg_iovlen; ++i) {
            if (memory_read(memory, (uintptr_t)vectors[i].iov_base, data + offset, vectors[i].iov_len) < 0) {
                error = errno; free(data); goto failed;
            }
            offset += vectors[i].iov_len;
        }
    } else if (memory_read(memory, pointer, data, (size_t)length) < 0) {
        error = errno; free(data); goto failed;
    }
    close(memory);
    if (valid_id(listener, r->id) < 0) { free(data); return 1; }
    char target[96];
    describe_target(&address, s->protocol, target, sizeof(target));
    if (observe(p, r, "authorize", target, 0, 0) < 0) {
        free(data); fill_response(response, r->id, 0, EIO); return 0;
    }
    if (observe(p, r, "delivery_begin", target, 0, 0) < 0) {
        free(data); fill_response(response, r->id, 0, EIO); return 0;
    }
    pid_t worker = start_worker(p);
    if (worker < 0) {
        error = errno; free(data);
        int logged = observe(p, r, "result", target, -1, error);
        int ended = observe(p, r, "delivery_end", target, 0, 0);
        fill_response(response, r->id, 0, logged < 0 || ended < 0 ? EIO : error); return 0;
    }
    if (worker == 0) {
        worker_close_other_sockets(p, s->fd);
        int delivery_error = 0;
        if (valid_id(listener, r->id) == 0) {
            ssize_t sent = sendto(s->fd, data, (size_t)length, flags | MSG_NOSIGNAL,
                address_size ? (struct sockaddr *)&address : NULL, address_size);
            int saved = sent < 0 ? errno : 0;
            if (observe(p, r, "result", target, sent, saved) < 0) saved = EIO;
            fill_response(response, r->id, sent < 0 ? 0 : sent, saved);
            if (send_response(listener, response) < 0) delivery_error = errno;
        } else {
            (void)observe(p, r, "result", target, -1, ECANCELED);
        }
        (void)observe(p, r, "delivery_end", target, 0, delivery_error);
        _exit(0);
    }
    free(data);
    return 1;
failed:
    close(memory);
    fill_response(response, r->id, 0, error);
    return 0;
}

static bool socket_option_allowed(int level, int option)
{
    if (level == SOL_SOCKET) {
        switch (option) {
        case SO_REUSEADDR: case SO_REUSEPORT: case SO_KEEPALIVE: case SO_BROADCAST:
        case SO_SNDBUF: case SO_RCVBUF: case SO_SNDTIMEO: case SO_RCVTIMEO:
        case SO_LINGER: case SO_OOBINLINE:
            return true;
        default: return false;
        }
    }
    if (level == IPPROTO_TCP) {
        switch (option) {
        case TCP_NODELAY: case TCP_KEEPIDLE: case TCP_KEEPINTVL: case TCP_KEEPCNT:
            return true;
        default: return false;
        }
    }
    return level == IPPROTO_IPV6 && option == IPV6_V6ONLY;
}

static int handle_setsockopt(struct net_policy *p, int listener,
                             const struct seccomp_notif *r, struct seccomp_notif_resp *response)
{
    struct owned_socket *s = lookup_socket(p, listener, r, r->data.args[0]);
    if (!s) { fill_response(response, r->id, 0, errno); return 0; }
    int level = (int)r->data.args[1], option = (int)r->data.args[2];
    if (!socket_option_allowed(level, option)) { fill_response(response, r->id, 0, EPERM); return 0; }
    unsigned char buffer[128];
    uint64_t size = r->data.args[4];
    if (size > sizeof(buffer)) { fill_response(response, r->id, 0, EINVAL); return 0; }
    int memory = memory_open(listener, r);
    if (memory < 0) { fill_response(response, r->id, 0, errno); return 0; }
    int rc = memory_read(memory, r->data.args[3], buffer, (size_t)size);
    int error = errno;
    close(memory);
    if (rc < 0) { fill_response(response, r->id, 0, error); return 0; }
    if (valid_id(listener, r->id) < 0) return 1;
    if (observe(p, r, "authorize", "", 0, 0) < 0) { fill_response(response, r->id, 0, EIO); return 0; }
    if (observe(p, r, "delivery_begin", "", 0, 0) < 0) { fill_response(response, r->id, 0, EIO); return 0; }
    rc = setsockopt(s->fd, level, option, buffer, (socklen_t)size);
    int saved = rc < 0 ? errno : 0;
    if (observe(p, r, "result", "", rc, saved) < 0) saved = EIO;
    if (observe(p, r, "delivery_end", "", 0, 0) < 0) saved = EIO;
    fill_response(response, r->id, 0, saved);
    return 0;
}

struct batch_message {
    struct sockaddr_storage address;
    socklen_t address_size;
    size_t length;
    unsigned char *data;
    char target[96];
};

static int handle_sendmmsg(struct net_policy *p, int listener,
                            const struct seccomp_notif *r, struct seccomp_notif_resp *response)
{
    struct owned_socket *s = lookup_socket(p, listener, r, r->data.args[0]);
    if (!s) { fill_response(response, r->id, 0, errno); return 0; }
    unsigned long count = r->data.args[2];
    if (!count || count > NET_MAX_IOV) { fill_response(response, r->id, 0, EINVAL); return 0; }
    /* Open once with write access to pin the target mm for msg_len updates;
     * a reused numeric TID cannot redirect those writes to another process. */
    int memory = broker_memory_open(listener, r, true);
    if (memory < 0) { fill_response(response, r->id, 0, errno); return 0; }
    if (valid_id(listener, r->id) < 0) { close(memory); return 1; }
    struct mmsghdr headers[NET_MAX_IOV];
    struct batch_message batch[NET_MAX_IOV] = {0};
    size_t total = 0;
    int error = 0;
    bool delivery = false;
    if (memory_read(memory, r->data.args[1], headers, count * sizeof(struct mmsghdr)) < 0) {
        error = errno; goto failed;
    }
    for (size_t i = 0; i < count; ++i) {
        struct msghdr *header = &headers[i].msg_hdr;
        if (header->msg_controllen || header->msg_iovlen > NET_MAX_IOV) { error = EOPNOTSUPP; goto failed; }
        if (header->msg_name) {
            if (copy_address(memory, (uintptr_t)header->msg_name, header->msg_namelen,
                              &batch[i].address, &batch[i].address_size) < 0) { error = errno; goto failed; }
        } else {
            socklen_t peer_size = sizeof(batch[i].address);
            if (getpeername(s->fd, (struct sockaddr *)&batch[i].address, &peer_size) < 0) {
                error = errno; goto failed;
            }
            if (s->protocol == IPPROTO_UDP) batch[i].address_size = peer_size;
        }
        if (!address_allowed(p, s->protocol, &batch[i].address)) { error = EACCES; goto failed; }
        describe_target(&batch[i].address, s->protocol, batch[i].target, sizeof(batch[i].target));
        struct iovec vectors[NET_MAX_IOV];
        if (memory_read(memory, (uintptr_t)header->msg_iov, vectors,
                         header->msg_iovlen * sizeof(struct iovec)) < 0) { error = errno; goto failed; }
        for (size_t j = 0; j < header->msg_iovlen; ++j) {
            if (vectors[j].iov_len > NET_MAX_MESSAGE - total) { error = EMSGSIZE; goto failed; }
            batch[i].length += vectors[j].iov_len;
            total += vectors[j].iov_len;
        }
        batch[i].data = malloc(batch[i].length ? batch[i].length : 1);
        if (!batch[i].data) { error = ENOMEM; goto failed; }
        size_t offset = 0;
        for (size_t j = 0; j < header->msg_iovlen; ++j) {
            if (memory_read(memory, (uintptr_t)vectors[j].iov_base,
                             batch[i].data + offset, vectors[j].iov_len) < 0) { error = errno; goto failed; }
            offset += vectors[j].iov_len;
        }
    }
    if (valid_id(listener, r->id) < 0) { error = ENOENT; goto failed; }
    for (size_t i = 0; i < count; ++i)
        if (observe(p, r, "authorize", batch[i].target, 0, 0) < 0) { error = EIO; goto failed; }
    if (observe(p, r, "delivery_begin", "", 0, 0) < 0) { error = EIO; goto failed; }
    delivery = true;
    pid_t worker = start_worker(p);
    if (worker < 0) { error = errno; goto failed; }
    if (worker == 0) {
        worker_close_other_sockets(p, s->fd);
        unsigned sent_count = 0;
        int saved = 0;
        for (size_t i = 0; i < count; ++i) {
            if (valid_id(listener, r->id) < 0) {
                saved = ECANCELED;
                if (observe(p, r, "cancelled", "", sent_count, saved) < 0) saved = EIO;
                break;
            }
            ssize_t sent = sendto(s->fd, batch[i].data, batch[i].length,
                (int)r->data.args[3] | MSG_NOSIGNAL,
                batch[i].address_size ? (struct sockaddr *)&batch[i].address : NULL,
                batch[i].address_size);
            saved = sent < 0 ? errno : 0;
            int observed = observe(p, r, "result", batch[i].target, sent, saved);
            if (sent < 0) break;
            ++sent_count;
            unsigned length = (unsigned)sent;
            uint64_t dest = r->data.args[1] + i * sizeof(struct mmsghdr) + offsetof(struct mmsghdr, msg_len);
            if (dest > INT64_MAX || pwrite(memory, &length, sizeof(length), (off_t)dest) != sizeof(length)) {
                saved = EFAULT;
                (void)observe(p, r, "copyback_error", batch[i].target, -1, saved);
                break;
            }
            if (observed < 0) { saved = EIO; break; }
        }
        /* Once a message was sent, report that partial count even if writing
         * msg_len or the audit stream failed. Never silently resend effects. */
        fill_response(response, r->id, sent_count, sent_count ? 0 : saved);
        if (observe(p, r, "batch_result", "", sent_count, sent_count ? 0 : saved) < 0 && !sent_count)
            response->error = -EIO;
        int delivery_error = send_response(listener, response) < 0 ? errno : 0;
        (void)observe(p, r, "delivery_end", "", sent_count, delivery_error);
        _exit(0);
    }
    for (size_t i = 0; i < count; ++i) free(batch[i].data);
    close(memory);
    return 1;
failed:
    for (size_t i = 0; i < count; ++i) free(batch[i].data);
    close(memory);
    if (delivery) {
        int logged = observe(p, r, "batch_result", "", 0, error);
        int ended = observe(p, r, "delivery_end", "", 0, 0);
        if (logged < 0 || ended < 0) error = EIO;
    }
    if (error == ENOENT) return 1;
    fill_response(response, r->id, 0, error);
    return 0;
}

static int handle_nonblocking(struct net_policy *p, int listener, const struct seccomp_notif *r,
                              struct seccomp_notif_resp *response)
{
    if ((unsigned long)r->data.args[1] != FIONBIO) { fill_response(response, r->id, 0, EPERM); return 0; }
    struct owned_socket *s = lookup_socket(p, listener, r, r->data.args[0]);
    if (!s) { fill_response(response, r->id, 0, errno); return 0; }
    int memory = memory_open(listener, r), enabled;
    if (memory < 0) { fill_response(response, r->id, 0, errno); return 0; }
    int rc = memory_read(memory, r->data.args[2], &enabled, sizeof(enabled));
    int saved = errno; close(memory);
    if (rc < 0) { fill_response(response, r->id, 0, saved); return 0; }
    if (valid_id(listener, r->id) < 0) return 1;
    if (observe(p, r, "authorize", "", 0, 0) < 0) { fill_response(response, r->id, 0, EIO); return 0; }
    if (observe(p, r, "delivery_begin", "", 0, 0) < 0) { fill_response(response, r->id, 0, EIO); return 0; }
    rc = ioctl(s->fd, FIONBIO, &enabled); saved = rc < 0 ? errno : 0;
    if (observe(p, r, "result", "", rc, saved) < 0) saved = EIO;
    if (observe(p, r, "delivery_end", "", 0, 0) < 0) saved = EIO;
    fill_response(response, r->id, 0, saved); return 0;
}

int network_handle(struct net_policy *p, int listener, const struct seccomp_notif *r,
                    struct seccomp_notif_resp *response)
{
    if (!p) { errno = EINVAL; return -1; }
    reap_workers(p);
    switch (r->data.nr) {
    case __NR_socket: return handle_socket(p, listener, r, response);
    case __NR_connect: return handle_connect(p, listener, r, response);
    case __NR_sendto: return handle_send(p, listener, r, response, false);
    case __NR_sendmsg: return handle_send(p, listener, r, response, true);
    case __NR_setsockopt: return handle_setsockopt(p, listener, r, response);
    case __NR_sendmmsg: return handle_sendmmsg(p, listener, r, response);
    case __NR_ioctl: return handle_nonblocking(p, listener, r, response);
    case __NR_bind: case __NR_listen: case __NR_accept: case __NR_accept4:
    case __NR_socketpair:
        fill_response(response, r->id, 0, EPERM); return 0;
    default: return -2;
    }
}

static bool decimal_name(const char *text)
{
    if (!*text) return false;
    for (; *text; ++text) if (*text < '0' || *text > '9') return false;
    return true;
}

static int compare_task_id(const void *left, const void *right)
{
    unsigned a = *(const unsigned *)left, b = *(const unsigned *)right;
    return a < b ? -1 : a > b;
}

#define NET_MAX_GC_TASKS 16384
struct task_snapshot { unsigned tids[NET_MAX_GC_TASKS]; size_t count; };

static int scan_task_fds(struct net_policy *p, unsigned pid, unsigned tid, bool *referenced)
{
    char path[96];
    snprintf(path, sizeof(path), "/proc/%u/task/%u/fd", pid, tid);
    DIR *fds = opendir(path);
    if (!fds) return -1;
    bool complete = true;
    for (;;) {
        errno = 0;
        struct dirent *fd = readdir(fds);
        if (!fd) { if (errno) complete = false; break; }
        if (!decimal_name(fd->d_name)) continue;
        struct stat st;
        if (fstatat(dirfd(fds), fd->d_name, &st, 0) < 0) {
            /* Even ENOENT can mean a handoff to a newly created FD table.
             * Defer retirement instead of assuming the object is unused. */
            complete = false;
            continue;
        }
        if (!S_ISSOCK(st.st_mode)) continue;
        for (size_t i = 0; i < CINCTA_NET_MAX_SOCKETS; ++i)
            if (p->sockets[i].fd >= 0 && p->sockets[i].inode == st.st_ino &&
                p->sockets[i].device == st.st_dev)
                referenced[i] = true;
    }
    if (closedir(fds) < 0) complete = false;
    return complete ? 0 : -1;
}

static int scan_group_tasks(struct net_policy *p, pid_t pgid,
                             struct task_snapshot *snapshot, bool *referenced)
{
    snapshot->count = 0;
    DIR *processes = opendir("/proc");
    if (!processes) return -1;
    bool complete = true;
    for (;;) {
        errno = 0;
        struct dirent *process = readdir(processes);
        if (!process) { if (errno) complete = false; break; }
        if (!decimal_name(process->d_name)) continue;
        unsigned pid;
        if (parse_unsigned(process->d_name, INT_MAX, &pid) < 0) { complete = false; continue; }
        pid_t group = getpgid((pid_t)pid);
        if (group < 0) { complete = false; continue; }
        if (group != pgid) continue;
        char path[80];
        snprintf(path, sizeof(path), "/proc/%u/task", pid);
        DIR *tasks = opendir(path);
        if (!tasks) { complete = false; continue; }
        for (;;) {
            errno = 0;
            struct dirent *task = readdir(tasks);
            if (!task) { if (errno) complete = false; break; }
            if (!decimal_name(task->d_name)) continue;
            unsigned tid;
            if (parse_unsigned(task->d_name, INT_MAX, &tid) < 0) { complete = false; continue; }
            if (snapshot->count == NET_MAX_GC_TASKS) {
                closedir(tasks); closedir(processes); errno = E2BIG; return -1;
            }
            snapshot->tids[snapshot->count++] = tid;
            if (scan_task_fds(p, pid, tid, referenced) < 0) complete = false;
        }
        if (closedir(tasks) < 0) complete = false;
    }
    if (closedir(processes) < 0) complete = false;
    qsort(snapshot->tids, snapshot->count, sizeof(unsigned), compare_task_id);
    return complete ? 0 : -1;
}

int network_gc(struct net_policy *p, pid_t pgid)
{
    if (!p || pgid <= 0) { errno = EINVAL; return -1; }
    reap_workers(p);
    bool referenced[CINCTA_NET_MAX_SOCKETS] = {false};
    struct task_snapshot *first = malloc(sizeof(*first)), *second = malloc(sizeof(*second));
    if (!first || !second) { free(first); free(second); return -1; }
    bool complete = scan_group_tasks(p, pgid, first, referenced) == 0;
    if (scan_group_tasks(p, pgid, second, referenced) < 0) complete = false;
    if (first->count != second->count ||
        memcmp(first->tids, second->tids, first->count * sizeof(unsigned))) complete = false;
    free(first); free(second);
    /* Both passes include every thread's FD table, including CLONE_THREAD
     * without CLONE_FILES. A changed task set or any failed read retires
     * nothing. Procfs still cannot provide an atomic fork/dup snapshot;
     * availability races never authorize a new destination. */
    if (complete) {
        for (size_t i = 0; i < CINCTA_NET_MAX_SOCKETS; ++i) {
            if (p->sockets[i].fd >= 0 && !referenced[i]) {
                close(p->sockets[i].fd); p->sockets[i].fd = -1;
            }
        }
    }
    return complete ? 0 : -1;
}

void network_destroy(struct net_policy *p)
{
    if (!p) return;
    for (size_t i = 0; i < CINCTA_NET_MAX_WORKERS; ++i) {
        if (p->workers[i] <= 0) continue;
        /* Only signal an unreaped direct child. A separately reaped PID may
         * already have been recycled; waitpid ECHILD prevents that signal. */
        int status;
        pid_t got = waitpid(p->workers[i], &status, WNOHANG);
        if (got == 0) {
            kill(p->workers[i], SIGKILL);
            do { got = waitpid(p->workers[i], &status, WNOHANG); } while (got < 0 && errno == EINTR);
        }
    }
    for (size_t i = 0; i < CINCTA_NET_MAX_SOCKETS; ++i)
        if (p->sockets[i].fd >= 0) close(p->sockets[i].fd);
    free(p);
}

static void quoted(FILE *out, const char *text)
{
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p > 126) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

void network_write_snapshot(FILE *out, const struct net_policy *p)
{
    fputc('[', out);
    if (p) for (size_t i = 0; i < p->endpoint_count; ++i) {
        const struct endpoint *e = &p->endpoints[i];
        char address[INET6_ADDRSTRLEN];
        if (i) fputc(',', out);
        inet_ntop(e->family, e->address, address, sizeof(address));
        fputs("{\"rule\":", out); quoted(out, e->source);
        fputs(",\"address\":", out); quoted(out, address);
        fprintf(out, ",\"prefix\":%u,\"protocol\":\"%s\",\"port_first\":%u,\"port_last\":%u}",
            e->prefix, e->protocol == IPPROTO_TCP ? "tcp" : "udp", e->port_first, e->port_last);
    }
    fputc(']', out);
}
