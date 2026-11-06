#ifndef CINCTA_H
#define CINCTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CINCTA_VERSION "0.1.0-preview.1"
#define CINCTA_MAX_RULES 128
#define CINCTA_MAX_ENV 128

enum path_mode { PATH_RO, PATH_RW, PATH_RX };
struct path_rule { const char *path; enum path_mode mode; };
struct config {
    struct path_rule rules[CINCTA_MAX_RULES];
    size_t rule_count;
    bool compat;
    bool network_host;
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

int supervise(const struct config *cfg);
int result_write(const struct config *cfg, const struct capabilities *caps,
                 const char *status, const char *stage, const char *message,
                 int exit_code, int term_signal, bool timed_out, bool cancelled,
                 bool cleanup_complete, uint64_t elapsed_ms);

#endif
