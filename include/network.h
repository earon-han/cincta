#ifndef CINCTA_NETWORK_H
#define CINCTA_NETWORK_H

#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#define CINCTA_NET_MAX_RULES 128
#define CINCTA_NET_MAX_SOCKETS 512
#define CINCTA_NET_MAX_WORKERS 64

struct net_policy;
typedef int (*network_observer)(const struct seccomp_notif *request,
                                const char *phase, const char *target,
                                long long value, int error,
                                void *context);

/* Rules: tcp:HOST_OR_CIDR:PORT[-PORT], udp:HOST_OR_CIDR:PORT[-PORT].
 * IPv6 literals must be bracketed. Host names resolve once before execution;
 * the resulting address set is immutable for this invocation. */
int network_prepare(const char *const *rules, size_t count,
                    struct net_policy **out, char *error, size_t error_size);
void network_destroy(struct net_policy *policy);
void network_write_snapshot(FILE *out, const struct net_policy *policy);
void network_observe(struct net_policy *policy, network_observer observer, void *context);

/* A handler owns no target pointers: copy first, validate the notification,
 * authorize the copy, then perform effects on broker-owned socket FDs.
 * Return 0 with response populated (caller sends), 1 if sent/delegated to a
 * bounded worker, -1 for supervisor failure, -2 if this is not a network call.
 * Workers are children of the broker, adopted by the monitor on failure, and included in its
 * subreaper cleanup. Never CONTINUE connect/sendmsg/setsockopt pointer checks. */
int network_handle(struct net_policy *policy, int listener,
                   const struct seccomp_notif *request,
                   struct seccomp_notif_resp *response);

/* Reap completed worker processes and close retained socket copies when no
 * process in the fixed payload group references them. Failure retains copies
 * conservatively; the caller must retry or report the cleanup failure. */
int network_gc(struct net_policy *policy, pid_t payload_pgid);

#endif
