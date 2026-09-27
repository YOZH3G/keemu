/* KEEMU native, unprivileged target-namespace script supervisor.
 * Owns only descendants of this docker-exec process. stdout is a length-framed
 * result, never direct script output. No host mounts, daemon or shell -c.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CAP (1024 * 1024)
#define MAX_PIDS 256
#define GRACE_MS 1500
#define CLEANUP_MS 4000

struct proc { pid_t pid, parent; unsigned long long start; char state; };
struct stream { unsigned char bytes[CAP]; size_t used; int truncated, fd; };
static struct stream out, err;
static struct proc processes[MAX_PIDS];
static size_t count;
static int io_failed;

static long long now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Parse Linux proc stat after the final ')' of comm (which may contain spaces). */
static int proc_stat(pid_t pid, struct proc *p) {
    char path[64], text[2048], *end, *field, *save;
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t length = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (length < 0 || length >= (ssize_t)sizeof(text) - 1) return -1;
    text[length] = 0;
    end = strrchr(text, ')');
    if (!end || end[1] != ' ') return -1;
    p->pid = pid;
    field = strtok_r(end + 2, " ", &save); /* field 3, state */
    if (!field || strlen(field) != 1) return -1;
    p->state = *field;
    field = strtok_r(NULL, " ", &save); /* field 4, ppid */
    if (!field) return -1;
    char *last;
    long parent = strtol(field, &last, 10);
    if (*last || parent < 0 || parent > INT32_MAX) return -1;
    p->parent = (pid_t)parent;
    for (int i = 5; i <= 22; i++) {
        field = strtok_r(NULL, " ", &save);
        if (!field) return -1;
    }
    p->start = strtoull(field, &last, 10);
    return *last ? -1 : 0;
}

static int scan(void) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end || pid <= 0 || pid > INT32_MAX) continue;
        if (count == MAX_PIDS) { closedir(dir); return -1; }
        struct proc p;
        if (!proc_stat((pid_t)pid, &p)) processes[count++] = p;
    }
    closedir(dir);
    return 0;
}

static int descended(pid_t pid, pid_t root) {
    for (size_t hops = 0; hops <= count; hops++) {
        if (pid == root) return 1;
        size_t i;
        for (i = 0; i < count && processes[i].pid != pid; i++) {}
        if (i == count || processes[i].parent == pid) return 0;
        pid = processes[i].parent;
    }
    return 0;
}

static int descendants(int sig, pid_t root) {
    if (scan()) return -1;
    int alive = 0;
    for (size_t i = 0; i < count; i++) {
        struct proc first = processes[i], check;
        if (first.pid == root || first.state == 'Z' ||
            !descended(first.pid, root)) continue;
        alive++;
        if (!sig) continue;
        /* pidfd pins identity while checking and signaling; never signal a PID
         * obtained from a stale shell-output or an unrelated process group. */
        int fd = syscall(SYS_pidfd_open, first.pid, 0);
        if (fd < 0) { if (errno != ESRCH) return -1; continue; }
        if (!proc_stat(first.pid, &check) && check.start == first.start &&
            check.state != 'Z' && descended(check.pid, root) &&
            syscall(SYS_pidfd_send_signal, fd, sig, NULL, 0) && errno != ESRCH) {
            close(fd);
            return -1;
        }
        close(fd);
    }
    return alive;
}

static void drain(struct stream *s) {
    unsigned char buf[65536];
    for (;;) {
        ssize_t n = read(s->fd, buf, sizeof buf);
        if (n > 0) {
            size_t left = CAP - s->used;
            size_t copy = (size_t)n < left ? (size_t)n : left;
            memcpy(s->bytes + s->used, buf, copy);
            s->used += copy;
            if (copy < (size_t)n) s->truncated = 1;
        } else if (!n) { close(s->fd); s->fd = -1; return; }
        else if (errno == EAGAIN || errno == EINTR) return;
        else { io_failed = 1; close(s->fd); s->fd = -1; return; }
    }
}

static void launch_failed(int fd) {
    char failed = '!';
    (void)write(fd, &failed, 1);
    _exit(125);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    char *end;
    long seconds = strtol(argv[1], &end, 10);
    char script[256];
    size_t length = strlen(argv[0]);
    if (*end || seconds < 1 || seconds > 600 || length < 8 ||
        length + 4 >= sizeof(script) || strcmp(argv[0] + length - 7, "/runner") ||
        argv[0][0] != '/' || prctl(PR_SET_CHILD_SUBREAPER, 1)) return 2;
    memcpy(script, argv[0], length - 6);
    memcpy(script + length - 6, "script.sh", 10);
    int a[2], b[2], ready[2];
    if (pipe2(a, O_CLOEXEC) || pipe2(b, O_CLOEXEC) ||
        pipe2(ready, O_CLOEXEC)) return 2;
    long long begin = now_ms();
    pid_t child = fork();
    if (child < 0) return 2;
    if (!child) {
        close(a[0]); close(b[0]); close(ready[0]);
        if (setsid() < 0 || dup2(a[1], STDOUT_FILENO) < 0 ||
            dup2(b[1], STDERR_FILENO) < 0) launch_failed(ready[1]);
        close(a[1]); close(b[1]);
        int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null < 0 || dup2(null, STDIN_FILENO) < 0) launch_failed(ready[1]);
        close(null);
        char **args = calloc((size_t)argc + 1, sizeof(char *));
        if (!args) launch_failed(ready[1]);
        args[0] = "/bin/sh";
        args[1] = script;
        for (int i = 2; i < argc; i++) args[i] = argv[i];
        char *env[] = {"PATH=/opt/bin:/opt/sbin:/bin:/sbin", "HOME=/opt", "LC_ALL=C", NULL};
        execve("/bin/sh", args, env);
        launch_failed(ready[1]);
    }
    close(a[1]); close(b[1]); close(ready[1]);
    out.fd = a[0]; err.fd = b[0];
    if (fcntl(out.fd, F_SETFL, O_NONBLOCK) || fcntl(err.fd, F_SETFL, O_NONBLOCK)) return 2;
    int main_status = 0, main_seen = 0, timed_out = 0, clean = 0, failed = 0;
    struct pollfd launch = {ready[0], POLLIN, 0};
    char launch_error;
    int launch_wait = poll(&launch, 1, 5000);
    if (launch_wait <= 0 || read(ready[0], &launch_error, 1) != 0) failed = 1;
    close(ready[0]);
    long long deadline = begin + seconds * 1000, kill_at = 0;
    long long limit = deadline + GRACE_MS + CLEANUP_MS;
    while (now_ms() < limit) {
        struct pollfd fds[2] = {{out.fd, POLLIN, 0}, {err.fd, POLLIN, 0}};
        if (poll(fds, 2, 25) < 0 && errno != EINTR) failed = 1;
        if (out.fd >= 0) drain(&out);
        if (err.fd >= 0) drain(&err);
        int status;
        pid_t reaped;
        while ((reaped = waitpid(-1, &status, WNOHANG)) > 0) {
            if (reaped == child) { main_status = status; main_seen = 1; }
        }
        int no_children = reaped < 0 && errno == ECHILD;
        if ((reaped < 0 && !no_children) || io_failed) failed = 1;
        int remaining = descendants(0, getpid());
        if (remaining < 0) failed = 1;
        if (main_seen && remaining == 0 && out.fd < 0 && err.fd < 0 &&
            no_children) { clean = !failed; break; }
        long long t = now_ms();
        if (!timed_out && t >= deadline) { timed_out = 1; kill_at = t + GRACE_MS; }
        if (timed_out) {
            if (descendants(t >= kill_at ? SIGKILL : SIGTERM, getpid()) < 0)
                failed = 1;
        }
        if (failed) { /* Even after a proof failure, try bounded tree cleanup. */
            descendants(SIGKILL, getpid());
        }
    }
    if (!clean) {
        long long until = now_ms() + CLEANUP_MS;
        while (now_ms() < until) {
            descendants(SIGKILL, getpid());
            int status;
            while (waitpid(-1, &status, WNOHANG) > 0) {}
            if (descendants(0, getpid()) == 0) break;
            usleep(25000);
        }
    }
    if (out.fd >= 0) { drain(&out); if (out.fd >= 0) close(out.fd); }
    if (err.fd >= 0) { drain(&err); if (err.fd >= 0) close(err.fd); }
    if (failed) clean = 0;
    int code = main_seen ? (WIFEXITED(main_status) ? WEXITSTATUS(main_status) :
                            WIFSIGNALED(main_status) ? 128 + WTERMSIG(main_status) : 125) : -1;
    long long duration = now_ms() - begin;
    if (printf("KEEMU1 %d %d %d %lld %zu %zu %d %d\n", code,
               timed_out, clean, duration, out.used, err.used,
               out.truncated, err.truncated) < 0 ||
        fwrite(out.bytes, 1, out.used, stdout) != out.used ||
        fwrite(err.bytes, 1, err.used, stdout) != err.used || fflush(stdout)) return 2;
    return 0;
}
