#define _GNU_SOURCE
#include "cincta.h"
#include "json.h"
#include "broker.h"
#include "network.h"
#include "resources.h"
#include "workspace.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The monitor opens this new file before any untrusted process starts. */
static int result_fd = -1;
int result_get_fd(void) { return result_fd; }
void result_close(void) { if (result_fd >= 0) close(result_fd); result_fd = -1; }
int result_reset(void)
{
    if (result_fd < 0) return 0;
    if (ftruncate(result_fd, 0) < 0) return -1;
    return lseek(result_fd, 0, SEEK_SET) < 0 ? -1 : 0;
}
static uint64_t setup_ms, run_ms, cleanup_ms;
void result_set_phases(uint64_t setup, uint64_t run, uint64_t cleanup)
{
    setup_ms = setup; run_ms = run; cleanup_ms = cleanup;
}
int result_open(const struct config *cfg)
{
    if (!cfg->result) return 0;
    if (result_fd >= 0) return 0;
    result_fd = open(cfg->result, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    return result_fd < 0 ? -1 : 0;
}

int result_write(const struct config *cfg, const struct capabilities *caps,
                 const char *status, const char *stage, const char *message,
                 int exit_code, int term_signal, bool timed_out, bool cancelled,
                 bool cleanup_complete, uint64_t elapsed_ms)
{
    FILE *f;
    bool active = (cfg->state && cfg->state->protections_active) || !strcmp(stage, "exec") || !strcmp(stage, "running");
    if (!cfg->result) return 0;
    if (result_fd < 0) { errno = EBADF; return -1; }
    f = fdopen(result_fd, "w");
    if (!f) { close(result_fd); return -1; }
    result_fd = -1;
    fprintf(f, "{\"schema_version\":1,\"version\":\"" CINCTA_VERSION "\",\"status\":");
    json_string(f, status);
    fprintf(f, ",\"stage\":"); json_string(f, stage);
    fprintf(f, ",\"message\":"); json_string(f, message);
    fprintf(f, ",\"exit_code\":%d,\"signal\":%d,\"timed_out\":%s,\"cancelled\":%s,"
        "\"cleanup_complete\":%s,\"elapsed_ms\":%llu,\"phase_ms\":{\"setup\":%llu,\"run\":%llu,\"cleanup\":%llu},\"protections\":{"
        "\"landlock_abi\":%d,\"seccomp\":%s,\"network\":\"%s\",\"ipc_scoped\":%s,\"caller_bound\":%s},"
        "\"unsupported\":[", exit_code, term_signal, timed_out ? "true" : "false",
        cancelled ? "true" : "false", cleanup_complete ? "true" : "false",
        (unsigned long long)(elapsed_ms + cfg->preparation_ms), (unsigned long long)(setup_ms + cfg->preparation_ms),
        (unsigned long long)run_ms, (unsigned long long)cleanup_ms,
        active ? caps->landlock_abi : 0,
        active && caps->seccomp ? "true" : "false", active ? (cfg->network_allowlist ? "allowlist" : cfg->network_host ? "host" : "none") : "unconfined",
        active && caps->landlock_abi >= 6 ? "true" : "false", cfg->caller_fd >= 0 ? "true" : "false");
    if (caps->landlock_abi < 6) json_string(f, "signal_and_abstract_unix_scopes_require_abi_6");
    if (cfg->caller_fd < 0) {
        if (caps->landlock_abi < 6) fputc(',', f);
        json_string(f, "caller_lifetime_unavailable_in_pid_namespace");
    }
    fprintf(f, "],\"dynamic\":%s,\"network_snapshot\":", cfg->state && cfg->state->dynamic_active ? "true" : "false");
    if (cfg->network) network_write_snapshot(f, cfg->network); else fputs("[]", f);
    fprintf(f, ",\"audit\":{\"enabled\":%s,\"mode\":\"%s\",\"records\":%llu,\"complete\":%s,\"path\":",
        cfg->audit ? "true" : "false", cfg->audit_syscalls ? "syscall_requests_and_broker_results" : "events",
        cfg->state ? (unsigned long long)cfg->state->audit_records : 0,
        cfg->audit && (!cfg->state || cfg->state->audit_failed || !cfg->state->audit_finished) ? "false" : "true");
    json_string(f, cfg->audit ? cfg->audit : "");
    fprintf(f, ",\"bytes\":%llu,\"max_bytes\":%u,\"max_records\":%u,\"limit_exceeded\":%s,\"delivery_pending\":%llu,\"native_open_fallbacks\":%llu}",
        cfg->state ? (unsigned long long)cfg->state->audit_bytes : 0, cfg->audit_max_bytes, cfg->audit_max_records,
        cfg->state && cfg->state->audit_limit_exceeded ? "true" : "false",
        cfg->state ? (unsigned long long)cfg->state->delivery_pending : 0,
        cfg->state ? (unsigned long long)cfg->state->native_open_fallbacks : 0);
    fputs(",\"workspace\":{\"enabled\":", f); fputs(cfg->workspace ? "true" : "false", f);
    if (cfg->workspace) {
        const struct workspace_ctx *w = cfg->workspace;
        fputs(",\"source\":", f); json_string(f, w->source);
        fputs(",\"root\":", f); json_string(f, w->root);
        fputs(",\"tree\":", f); json_string(f, w->tree);
        fprintf(f, ",\"retained\":%s,\"exported\":%s,\"executable\":%s,\"changes\":%llu,\"copied_files\":%llu,\"copied_bytes\":%llu",
            w->retained ? "true" : "false", w->exported ? "true" : "false",
            cfg->workspace_exec ? "true" : "false",
            (unsigned long long)w->changes, (unsigned long long)w->copied_files, (unsigned long long)w->copied_bytes);
    }
    fputs("},\"resources\":{\"enabled\":", f);
    const struct resource_ctx *r = cfg->resources;
    fputs(r && r->enabled ? "true" : "false", f);
    if (r && r->enabled) {
        fputs(",\"path\":", f); json_string(f, r->path);
        fprintf(f, ",\"memory_peak_supported\":%s,\"pids_peak_supported\":%s",
            r->memory_peak_supported ? "true" : "false", r->pids_peak_supported ? "true" : "false");
        fprintf(f, ",\"removed\":%s,\"populated\":%s,\"memory_peak\":%llu,\"pids_peak\":%llu,"
            "\"cpu_usage_usec\":%llu,\"cpu_nr_throttled\":%llu,\"memory_oom_kill\":%llu,\"pids_limit_hits\":%llu,\"swap_disabled\":%s,\"cpu_budget_exhausted\":%s",
            r->removed ? "true" : "false", r->populated ? "true" : "false",
            (unsigned long long)r->memory_peak, (unsigned long long)r->pids_peak,
            (unsigned long long)r->cpu_usage_usec, (unsigned long long)r->cpu_nr_throttled,
            (unsigned long long)r->memory_oom_kill, (unsigned long long)r->pids_limit_hits,
            r->swap_disabled ? "true" : "false",
            cfg->state && cfg->state->resource_cpu_exhausted ? "true" : "false");
    }
    fputs("}}\n", f);
    int failed = ferror(f);
    if (fflush(f) != 0) failed = 1;
    if (fsync(fileno(f)) != 0) failed = 1;
    if (fclose(f) != 0) failed = 1;
    return failed ? -1 : 0;
}
