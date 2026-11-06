#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct shared {
    int socket;
    unsigned short port;
    atomic_int start;
    atomic_int done;
    atomic_int error;
};

static void pause_ms(long ms)
{
    struct timespec time = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000};
    while (nanosleep(&time, &time) < 0 && errno == EINTR) {}
}

static int private_fd_thread(void *argument)
{
    struct shared *shared = argument;
    while (!atomic_load_explicit(&shared->start, memory_order_acquire)) pause_ms(1);
    /* The TGID's FD table now has no reference to this socket. Let several
     * GC periods pass before this private FD table uses its retained copy. */
    pause_ms(700);
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(shared->port)};
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int error = 0;
    if (connect(shared->socket, (struct sockaddr *)&peer, sizeof(peer)) < 0) error = errno;
    if (!error && write(shared->socket, "hello", 5) != 5) error = EIO;
    if (!error) {
        char data[5];
        size_t read_size = 0;
        while (read_size < sizeof(data)) {
            ssize_t got = read(shared->socket, data + read_size, sizeof(data) - read_size);
            if (got <= 0) { error = EIO; break; }
            read_size += (size_t)got;
        }
        if (!error && (data[0] != 'h' || data[4] != 'o')) error = EIO;
    }
    close(shared->socket);
    atomic_store_explicit(&shared->error, error, memory_order_relaxed);
    atomic_store_explicit(&shared->done, 1, memory_order_release);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    char *end;
    unsigned long port = strtoul(argv[1], &end, 10);
    if (!*argv[1] || *end || port == 0 || port > 65535) return 2;
    struct shared shared = {.port = (unsigned short)port};
    shared.socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (shared.socket < 0) return 3;
    const size_t stack_size = 1024 * 1024;
    char *stack = malloc(stack_size);
    if (!stack) return 4;
    /* CLONE_THREAD requires SIGHAND+VM, but does NOT require CLONE_FILES. */
    if (clone(private_fd_thread, stack + stack_size,
              CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, &shared) < 0) return 5;
    close(shared.socket);
    atomic_store_explicit(&shared.start, 1, memory_order_release);
    for (unsigned i = 0; i < 500 && !atomic_load_explicit(&shared.done, memory_order_acquire); ++i)
        pause_ms(10);
    if (!atomic_load_explicit(&shared.done, memory_order_acquire)) return 6;
    int error = atomic_load_explicit(&shared.error, memory_order_relaxed);
    printf("{\"private_thread_fd_errno\":%d}\n", error);
    /* Stack is intentionally reclaimed by process exit after the raw thread;
     * freeing it concurrently with clone wrapper teardown would be unsafe. */
    return error ? 1 : 0;
}
