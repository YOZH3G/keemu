/* P0-05 native PID 1 correction for the mixed amd64/AArch64 image.
 * The keeper must not inherit PID 1's handled stop signals: otherwise it
 * loops in pause() instead of terminating when the parent forwards them.
 * A successful stop requires observing the keeper's exact signaled exit.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static volatile sig_atomic_t reap_requested;
static pid_t keeper;

static void on_signal(int sig) {
    if (sig == SIGCHLD) reap_requested = 1;
    else stopping = sig;
}

int main(void) {
    struct sigaction action = {0};
    sigemptyset(&action.sa_mask);
    action.sa_handler = on_signal;
    if (sigaction(SIGTERM, &action, 0) || sigaction(SIGINT, &action, 0) ||
        sigaction(SIGCHLD, &action, 0)) return 1;
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous)) return 1;
    keeper = fork();
    if (keeper < 0) return 1;
    if (keeper == 0) {
        struct sigaction defaults = {0};
        defaults.sa_handler = SIG_DFL;
        sigemptyset(&defaults.sa_mask);
        if (sigaction(SIGTERM, &defaults, 0) ||
            sigaction(SIGINT, &defaults, 0) ||
            sigaction(SIGCHLD, &defaults, 0)) _exit(1);
        if (sigprocmask(SIG_SETMASK, &previous, 0)) _exit(1);
        for (;;) pause();
    }
    for (;;) {
        if (reap_requested || stopping) {
            int status;
            pid_t child;
            reap_requested = 0;
            while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
                if (child == keeper && !stopping) return 1;
            }
            if (stopping) {
                int forwarded = stopping;
                if (kill(keeper, forwarded) < 0) return 1;
                do {
                    child = waitpid(keeper, &status, 0);
                } while (child < 0 && errno == EINTR);
                if (child != keeper || !WIFSIGNALED(status) ||
                    WTERMSIG(status) != forwarded) return 1;
                while (waitpid(-1, &status, WNOHANG) > 0) {}
                return 0;
            }
        }
        sigsuspend(&previous);
    }
}
