#ifndef CINCTA_WORKSPACE_H
#define CINCTA_WORKSPACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/limits.h>
#include <sys/types.h>

#define WORKSPACE_DEFAULT_MAX_FILES UINT64_C(100000)
#define WORKSPACE_DEFAULT_MAX_BYTES (UINT64_C(1024) * 1024 * 1024)

/* No persistent descriptor: CLI/monitor descriptor sanitization may close FDs.
 * Reopening verifies the private root's device/inode before any operation. */
struct workspace_ctx {
    char source[PATH_MAX];
    char root[PATH_MAX];
    char tree[PATH_MAX];
    uint64_t max_files;
    uint64_t max_bytes;
    uint64_t copied_files;
    uint64_t copied_bytes;
    uint64_t changes;
    dev_t root_dev;
    ino_t root_ino;
    bool prepared;
    bool retained;
    bool exported;
};

/* source and parent are existing absolute directories. parent==NULL means
 * /tmp. Neither parent nor a newly created private root may lie in source.
 * source is copied to a private baseline then an independent working tree.
 * Existing relative symlinks confined to the root are preserved as links;
 * openat2 verifies their complete resolution, including intermediate links.
 * Absolute/escaping/dangling links and special files are rejected. Zero limits use
 * defaults. On failure remove only objects created by this invocation. */
int workspace_prepare(const char *source, const char *parent,
                      uint64_t max_files, uint64_t max_bytes,
                      struct workspace_ctx *ctx, char *error, size_t error_size);

/* Call only after ALL payload descendants have actually been reaped.
 * diff_path is an optional exclusive new JSON report; export_path is an
 * optional exclusive new directory receiving the complete final tree.
 * No changes are ever applied to source. keep retains the private root for
 * review; otherwise remove it after successful diff/export. On failure the
 * private snapshot remains available for review, with ctx->retained=true.
 * A symlink introduced by payload is revalidated; unsafe links fail export. */
int workspace_finish(struct workspace_ctx *ctx, const char *diff_path,
                     const char *export_path, bool keep,
                     char *error, size_t error_size);

/* Safely delete the private snapshot without following links. Idempotent after
 * successful deletion. Never call while a live workload can still write it. */
int workspace_discard(struct workspace_ctx *ctx, char *error, size_t error_size);

#endif
