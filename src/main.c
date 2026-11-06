#define _GNU_SOURCE
#include "cincta.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *out)
{
    fprintf(out,
        "cincta " CINCTA_VERSION " (Linux x86_64/aarch64)\n"
        "Usage: cincta probe\n"
        "       cincta run [OPTIONS] -- COMMAND [ARGS...]\n"
        "  --ro PATH / --rw PATH / --rx PATH   Explicit absolute path grants\n"
        "  --cwd PATH                         Working directory\n"
        "  --network none|host                Default: none (all sockets denied)\n"
        "  --compat                           Explicit ABI 3-5 IPC scope downgrade\n"
        "  --timeout-ms N                     Wall time (default 30000; 0 unlimited)\n"
        "  --memory-mb N                      RLIMIT_AS (default 512)\n"
        "  --cpu-seconds N                    RLIMIT_CPU (default 30)\n"
        "  --processes N                      Per-UID RLIMIT_NPROC (default 256)\n"
        "  --nofile N                         RLIMIT_NOFILE (default 128)\n"
        "  --env KEY=VALUE                    Add environment variable\n"
        "  --result PATH                      Exclusive new JSON result file\n"
        "No implicit filesystem grants. Environment starts with PATH and LANG.\n"
        "Strict mode requires Landlock ABI 6; compat still requires ABI 3 + BPF.\n");
}

static int bad(const char *message, const char *arg)
{
    fprintf(stderr, "cincta: %s: %s\n", message, arg);
    return 125;
}

static bool number(const char *s, unsigned *value)
{
    char *end = NULL;
    unsigned long n;
    if (!*s || *s < '0' || *s > '9') return false;
    errno = 0;
    n = strtoul(s, &end, 10);
    if (errno || *end || n > UINT_MAX) return false;
    *value = (unsigned)n;
    return true;
}

static bool env_valid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || *p == '_')) return false;
    for (++p; *p && *p != '='; ++p)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || *p == '_')) return false;
    return *p == '=';
}

int main(int argc, char **argv)
{
    struct config cfg = { .timeout_ms = 30000, .memory_mb = 512,
        .cpu_seconds = 30, .processes = 256, .nofile = 128 };
    char cwd[PATH_MAX];
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "help"))) {
        usage(stdout); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts(CINCTA_VERSION); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "probe")) {
        struct capabilities caps = {0};
        if (security_probe(&caps) < 0) return bad("probe failed", strerror(errno));
        printf("{\"schema_version\":1,\"landlock_abi\":%d,\"landlock_errno\":%d,"
               "\"seccomp\":%s,\"seccomp_errno\":%d,\"strict_supported\":%s,"
               "\"compat_supported\":%s}\n", caps.landlock_abi, caps.landlock_errno,
               caps.seccomp ? "true" : "false", caps.seccomp_errno,
               caps.landlock_abi >= 6 && caps.seccomp ? "true" : "false",
               caps.landlock_abi >= 3 && caps.seccomp ? "true" : "false");
        return 0;
    }
    if (argc < 4 || strcmp(argv[1], "run")) { usage(stderr); return 125; }
    if (!getcwd(cwd, sizeof(cwd))) return bad("getcwd failed", strerror(errno));
    cfg.cwd = cwd;
    cfg.env[cfg.env_count++] = "PATH=/usr/bin:/bin";
    cfg.env[cfg.env_count++] = "LANG=C";
    for (int i = 2; i < argc; ++i) {
        const char *opt = argv[i];
        if (!strcmp(opt, "--")) {
            if (i + 1 == argc) return bad("missing command", opt);
            cfg.command = &argv[i + 1]; break;
        }
        if (!strcmp(opt, "--compat")) { cfg.compat = true; continue; }
        if (i + 1 >= argc) return bad("missing option value", opt);
        const char *val = argv[++i];
        if (!strcmp(opt, "--ro") || !strcmp(opt, "--rw") || !strcmp(opt, "--rx")) {
            if (*val != '/') return bad("path must be absolute", val);
            if (cfg.rule_count == CINCTA_MAX_RULES) return bad("too many path rules", opt);
            cfg.rules[cfg.rule_count++] = (struct path_rule){val,
                !strcmp(opt, "--ro") ? PATH_RO : !strcmp(opt, "--rw") ? PATH_RW : PATH_RX};
        } else if (!strcmp(opt, "--cwd")) {
            if (*val != '/') return bad("cwd must be absolute", val);
            cfg.cwd = val;
        } else if (!strcmp(opt, "--result")) {
            if (cfg.result) return bad("duplicate result option", opt);
            if (*val != '/') return bad("result path must be absolute", val);
            cfg.result = val;
        } else if (!strcmp(opt, "--network")) {
            if (strcmp(val, "none") && strcmp(val, "host")) return bad("invalid network mode", val);
            cfg.network_host = !strcmp(val, "host");
        } else if (!strcmp(opt, "--env")) {
            if (!env_valid(val)) return bad("invalid environment assignment", val);
            if (cfg.env_count == CINCTA_MAX_ENV) return bad("too many environment variables", opt);
            size_t len = (size_t)(strchr(val, '=') - val) + 1;
            bool replaced = false;
            for (size_t j = 0; j < cfg.env_count; ++j) {
                if (!strncmp(cfg.env[j], val, len)) { cfg.env[j] = argv[i]; replaced = true; break; }
            }
            if (!replaced) cfg.env[cfg.env_count++] = argv[i];
        } else {
            unsigned n;
            if (!number(val, &n)) return bad("invalid numeric option", val);
            if (!strcmp(opt, "--timeout-ms")) cfg.timeout_ms = n;
            else if (!strcmp(opt, "--memory-mb") && n) cfg.memory_mb = n;
            else if (!strcmp(opt, "--cpu-seconds") && n) cfg.cpu_seconds = n;
            else if (!strcmp(opt, "--processes") && n) cfg.processes = n;
            else if (!strcmp(opt, "--nofile") && n >= 16) cfg.nofile = n;
            else return bad("unknown option or invalid limit", opt);
        }
    }
    if (!cfg.command) return bad("missing command separator", "--");
    return supervise(&cfg);
}
