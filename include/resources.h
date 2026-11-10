#ifndef CINCTA_RESOURCES_H
#define CINCTA_RESOURCES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>

struct config;

/* Directory identity is checked whenever it is reopened. No descriptor is
 * retained across calls: the launcher may sanitize inherited descriptors. The
 * delegated parent must remain trusted and must not be writable by payload. */
struct resource_ctx {
    char parent[PATH_MAX];
    char path[PATH_MAX];
    dev_t device;
    ino_t inode;
    bool enabled;
    bool removed;
    bool kill_supported;
    bool memory_available;
    bool pids_available;
    bool memory_peak_supported;
    bool swap_disabled;
    bool pids_peak_supported;
    bool populated;
    unsigned memory_mb;
    unsigned pids_max;
    unsigned cpu_percent;
    unsigned cpu_budget_ms;
    uint64_t memory_current;
    uint64_t memory_peak;
    uint64_t pids_current;
    uint64_t pids_peak;
    uint64_t cpu_usage_usec;
    uint64_t cpu_user_usec;
    uint64_t cpu_system_usec;
    uint64_t cpu_nr_throttled;
    uint64_t cpu_throttled_usec;
    uint64_t memory_oom;
    uint64_t memory_oom_kill;
    uint64_t pids_limit_hits;
};

/* Explicit limits require cfg->cgroup_parent. The caller must already run in
 * its delegated subtree (or possess the ancestor migration permission). This
 * function never enables parent/global controllers or changes delegation.
 * Creating/configuring a group must complete before payload is released. */
int resource_prepare(const struct config *cfg, struct resource_ctx *ctx,
                     char *error, size_t error_size);

/* pid must be a live, pinned child held behind the launcher's exec barrier.
 * Attach and verify membership before allowing it to execute/fork user code. */
int resource_attach(struct resource_ctx *ctx, pid_t pid,
                    char *error, size_t error_size);

/* cgroup.kill is supplemental. On kernels without it, returns success with
 * kill_supported=false; the launcher must still kill/reap its descendants. */
int resource_kill(struct resource_ctx *ctx, char *error, size_t error_size);
int resource_sample(struct resource_ctx *ctx, char *error, size_t error_size);
bool resource_budget_exceeded(const struct resource_ctx *ctx,
                              const struct config *cfg);

/* Call after actual descendant reaping. Preserve final statistics then remove
 * only this invocation's empty group. A populated or replaced group fails. */
int resource_finish(struct resource_ctx *ctx, char *error, size_t error_size);

#endif
