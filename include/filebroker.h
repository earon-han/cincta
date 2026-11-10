#ifndef CINCTA_FILEBROKER_H
#define CINCTA_FILEBROKER_H

#include "cincta.h"
#include <linux/seccomp.h>

#define CINCTA_FILE_MAX_WORKERS 32

/* Optional --audit-syscalls path. The broker snapshots the path/flags and
 * pins the caller's directory, then a disposable worker installs equivalent
 * Landlock rules before opening. No pathname-based CONTINUE authorization.
 * Shared delivery_pending covers the whole worker operation from before fork
 * through result/response handling; a forcibly killed worker leaves it pending.
 * 1: worker owns response; 0: response populated; -1: internal fatal failure;
 * -2: not a supported file-open syscall. */
int filebroker_handle(const struct config *cfg, int listener,
                      const struct seccomp_notif *request,
                      struct seccomp_notif_resp *response);

/* Reaps only this module's own workers. destroy sends SIGKILL but never blocks;
 * monitor's subreaper cleanup must still wait all descendants to ECHILD. */
void filebroker_reap(void);
void filebroker_destroy(void);

#endif
