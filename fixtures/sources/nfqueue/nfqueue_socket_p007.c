/* P0-07 non-mutating NFNETLINK socket preflight. Never sends a queue bind or verdict. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) {
        fprintf(stderr, "NETLINK_NETFILTER socket: %s\n", strerror(errno));
        return 1;
    }
    puts("NETLINK_NETFILTER socket opened; NFQUEUE bind and verdict NOT attempted");
    close(fd);
    return 0;
}
