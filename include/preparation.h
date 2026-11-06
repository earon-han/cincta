#ifndef CINCTA_PREPARATION_H
#define CINCTA_PREPARATION_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct config;
struct workspace_ctx;
struct resource_ctx;
struct preparation_shared;

struct preparation_guard {
    pid_t pid;
    int control_fd;
    int status_fd;
    struct preparation_shared *shared;
    bool active;
    bool handed_over;
};

/* Call before any preparation artifacts are created. Guardian itself creates
 * a private 0700 container inside requested_parent (NULL -> /tmp), pins its
 * identity, then reports READY. Returns shared mmap workspace/resource ctx.
 * The caller must validate requested_parent lies outside workspace SOURCE.
 * No guardian inherits an eventual execution control-pipe write end: this
 * function runs before supervise creates that pipe. */
int preparation_start(struct workspace_ctx **workspace,
                      struct resource_ctx **resources,
                      const char *requested_parent,
                      struct preparation_guard *guard,
                      char *error, size_t error_size);

const char *preparation_workspace_parent(const struct preparation_guard *guard);

/* Trusted pre-payload RPC: guardian creates/configures requested cgroup itself.
 * This closes resource_prepare's mkdir-before-ctx.enabled cancellation window.
 * cfg->resources must refer to the resource ctx returned by start. */
int preparation_resources(struct preparation_guard *guard, const struct config *cfg,
                          char *error, size_t error_size);

/* Parent calls after monitor fork succeeds, BEFORE allowing monitor to launch
 * payload. Atomically transfers cleanup responsibility, checks ACK and reaps
 * guardian. Shared contexts remain mapped for monitor/CLI recovery. */
int preparation_handover(struct preparation_guard *guard, pid_t monitor_pid,
                         char *error, size_t error_size);

/* Monitor/CLI may each call after workspace/resource finish. Deletes only the
 * already-pinned empty container; keep=true retains it with review snapshot.
 * Does not disarm, wait or unmap shared ctx. Idempotent when already absent. */
int preparation_cleanup_container(struct preparation_guard *guard, bool keep,
                                  char *error, size_t error_size);

/* Caller first cleans any unhanded artifacts (workspace_discard/resources).
 * Disarms/reaps any still-running guardian, removes an empty container when
 * no retained workspace remains, and unmaps ctx only in this process. Return
 * -1 on failed protocol/cleanup; the guardian never guesses path ownership. */
int preparation_finish(struct preparation_guard *guard, char *error, size_t error_size);

#endif
