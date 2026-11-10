#ifndef CINCTA_BROKER_H
#define CINCTA_BROKER_H
#include "cincta.h"
#include <stdatomic.h>
#include <linux/seccomp.h>

struct run_state {
    _Atomic unsigned long long requests, continued, brokered, denied, audit_records;
    _Atomic unsigned long long audit_bytes, audit_reserved_bytes, audit_reserved_records;
    _Atomic bool audit_failed;
    _Atomic bool audit_finished;
    _Atomic bool audit_limit_exceeded;
    _Atomic unsigned long long gc_deferred;
    _Atomic unsigned long long delivery_pending, native_open_fallbacks;
    int audit_fd;
    bool dynamic_active;
    bool protections_active;
    bool workspace_finished;
    bool workspace_failed;
    bool resource_active;
    bool resource_removed;
    bool resource_cpu_exhausted;
    unsigned long long tree_cpu_usec, tree_memory_peak, tree_pids_peak;
    char resource_path[4096];
};
int broker_open(struct config *cfg, char *error, size_t size);
void broker_close(struct config *cfg);
int broker_send_listener(int transport, int listener);
/* 1 received, 0 still waiting, -1 malformed/error. */
int broker_receive_listener(int transport);
/* Handle a bounded batch, keeping lifecycle cancellation responsive. */
int broker_drain(const struct config *cfg, int listener, int abi);
int broker_run(const struct config *cfg, int listener, int abi, pid_t payload_group, int memory_channel);
int broker_memory_open(int listener, const struct seccomp_notif *request, bool writable);
int broker_service_memory(int channel, int listener);
int broker_event(const struct config *cfg, const char *kind,
                 const struct seccomp_notif *req, const char *target,
                 long long value, int error);
#endif
