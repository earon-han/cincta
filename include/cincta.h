#ifndef CINCTA_H
#define CINCTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CINCTA_VERSION "0.2.0-preview.1"
#define CINCTA_MAX_RULES 128
#define CINCTA_MAX_ENV 128

enum path_mode { PATH_RO, PATH_RW, PATH_RX };
struct path_rule { const char *path; enum path_mode mode; };
struct net_policy;
struct workspace_ctx;
struct run_state;
struct resource_ctx;
struct preparation_guard;
struct seccomp_data;
struct config {
    int caller_fd; /* Original caller TGID pidfd; -1 when the PID namespace hides the parent. */
    struct path_rule rules[CINCTA_MAX_RULES];
    int rule_fds[CINCTA_MAX_RULES];
    char *rule_targets[CINCTA_MAX_RULES];
    bool policy_pinned;
    size_t rule_count;
    bool compat;
    bool network_host;
    bool network_allowlist;
    struct net_policy *network;
    bool metadata;
    const char *audit;
    bool audit_syscalls;
    unsigned audit_max_bytes;
    unsigned audit_max_records;
    int notify_transport;
    struct run_state *state;
    const char *cgroup_parent;
    unsigned tree_memory_mb;
    unsigned tree_pids;
    unsigned tree_cpu_percent;
    unsigned tree_cpu_ms;
    struct resource_ctx *resources;
    struct preparation_guard *preparation;
    struct workspace_ctx *workspace;
    const char *workspace_diff;
    const char *workspace_export;
    bool workspace_keep;
    bool workspace_exec;
    uint64_t preparation_ms;
    const char *cwd;
    const char *result;
    char *env[CINCTA_MAX_ENV + 1];
    size_t env_count;
    unsigned timeout_ms;
    unsigned memory_mb;
    unsigned cpu_seconds;
    unsigned processes;
    unsigned nofile;
    char **command;
};
struct capabilities { int landlock_abi; int landlock_errno; bool seccomp; int seccomp_errno; };

/* Probe runs irreversible seccomp operations in a disposable child. */
int security_probe(struct capabilities *caps);
/* Fully validate pinned O_PATH rules before restricting; no implicit grants.
 * Set NNP, clear capabilities, apply Landlock, then seccomp. Close ruleset FDs.
 * On failure return -1 with an actionable message; caller must never exec. */
int security_apply(const struct config *cfg, struct capabilities *caps,
                   char *error, size_t error_size);
/* Optional notification listener is created by security_apply in payload.
 * Transfer to monitor, then install lockdown before running user code. */
int security_listener(void);
int security_pin_policy(struct config *cfg, char *error, size_t size);
void security_release_policy(struct config *cfg);
int security_lockdown(const struct config *cfg);
int security_restrict_files(const struct config *cfg, char *error, size_t size);
int security_drop_capabilities(void);
uint32_t security_decide(const struct config *cfg, int abi,
                         const struct seccomp_data *data);

int supervise(const struct config *cfg);
int caller_capture(int *fd);
/* 1 alive/no visible caller, 0 exited, -1 inspection failed. */
int caller_alive(int fd);
int result_open(const struct config *cfg);
int result_get_fd(void);
void result_close(void);
int result_write(const struct config *cfg, const struct capabilities *caps,
                 const char *status, const char *stage, const char *message,
                 int exit_code, int term_signal, bool timed_out, bool cancelled,
                 bool cleanup_complete, uint64_t elapsed_ms);

#endif
