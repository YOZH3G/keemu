/* Native static PID 1 for the mixed amd64/AArch64 image.
 * This source is project-owned; no target application is run by this process.
 * Docker-exec processes may be adopted and reaped while the environment is live.
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
                if (kill(keeper, stopping) < 0 && errno != ESRCH) return 1;
                while (waitpid(-1, &status, WNOHANG) > 0) {}
                return 0;
            }
        }
        sigsuspend(&previous);
    }
}
