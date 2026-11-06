#define _GNU_SOURCE
#include "cincta.h"
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
    result_fd = open(cfg->result, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    return result_fd < 0 ? -1 : 0;
}

static void json_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(f, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

int result_write(const struct config *cfg, const struct capabilities *caps,
                 const char *status, const char *stage, const char *message,
                 int exit_code, int term_signal, bool timed_out, bool cancelled,
                 bool cleanup_complete, uint64_t elapsed_ms)
{
    FILE *f;
    bool active = !strcmp(stage, "exec") || !strcmp(stage, "running");
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
        "\"landlock_abi\":%d,\"seccomp\":%s,\"network\":\"%s\",\"ipc_scoped\":%s},"
        "\"unsupported\":[", exit_code, term_signal, timed_out ? "true" : "false",
        cancelled ? "true" : "false", cleanup_complete ? "true" : "false",
        (unsigned long long)elapsed_ms, (unsigned long long)setup_ms,
        (unsigned long long)run_ms, (unsigned long long)cleanup_ms,
        active ? caps->landlock_abi : 0,
        active && caps->seccomp ? "true" : "false", active ? (cfg->network_host ? "host" : "none") : "unconfined",
        active && caps->landlock_abi >= 6 ? "true" : "false");
    if (caps->landlock_abi < 6) json_string(f, "signal_and_abstract_unix_scopes_require_abi_6");
    fprintf(f, "]}\n");
    int failed = ferror(f);
    if (fflush(f) != 0) failed = 1;
    if (fsync(fileno(f)) != 0) failed = 1;
    if (fclose(f) != 0) failed = 1;
    return failed ? -1 : 0;
}
