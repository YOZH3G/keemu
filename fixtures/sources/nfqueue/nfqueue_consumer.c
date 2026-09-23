#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 8192
#ifndef NLA_DATA
#define NLA_DATA(attribute) ((void *)((char *)(attribute) + NLA_HDRLEN))
#endif

static volatile sig_atomic_t keep_running = 1;
static uint64_t accepted = 0;
static uint64_t dropped = 0;
static unsigned short queue_number;
static uint32_t verdict;

static void stop_consumer(int signal_number) {
    (void)signal_number;
    keep_running = 0;
}

static int send_message(int fd, struct nlmsghdr *header) {
    struct sockaddr_nl destination = { .nl_family = AF_NETLINK };
    return sendto(fd, header, header->nlmsg_len, 0,
                  (const struct sockaddr *)&destination, sizeof(destination));
}

static void add_attribute(struct nlmsghdr *header, unsigned short type,
                          const void *data, size_t length) {
    struct nlattr *attribute = (struct nlattr *)((char *)header + NLMSG_ALIGN(header->nlmsg_len));
    attribute->nla_type = type;
    attribute->nla_len = (unsigned short)(NLA_ALIGN(sizeof(*attribute)) + length);
    memcpy(NLA_DATA(attribute), data, length);
    header->nlmsg_len = NLMSG_ALIGN(header->nlmsg_len) + NLA_ALIGN(attribute->nla_len);
}

static int configure_queue(int fd, unsigned short queue, unsigned char command) {
    char buffer[NLMSG_SPACE(sizeof(struct nfgenmsg)) + NLA_ALIGN(sizeof(struct nlattr)) +
                sizeof(struct nfqnl_msg_config_cmd)] = {0};
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    struct nfgenmsg *family = (struct nfgenmsg *)NLMSG_DATA(header);
    struct nfqnl_msg_config_cmd config = {
        .command = command,
        .pf = htons(AF_INET),
    };

    header->nlmsg_len = NLMSG_LENGTH(sizeof(*family));
    header->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    family->nfgen_family = AF_UNSPEC;
    family->version = NFNETLINK_V0;
    family->res_id = htons(queue);
    add_attribute(header, NFQA_CFG_CMD, &config, sizeof(config));
    return send_message(fd, header);
}

static int set_copy_mode(int fd, unsigned short queue) {
    char buffer[NLMSG_SPACE(sizeof(struct nfgenmsg)) + NLA_ALIGN(sizeof(struct nlattr)) +
                sizeof(struct nfqnl_msg_config_params)] = {0};
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    struct nfgenmsg *family = (struct nfgenmsg *)NLMSG_DATA(header);
    struct nfqnl_msg_config_params params = {
        .copy_range = htonl(0xffff),
        .copy_mode = NFQNL_COPY_PACKET,
    };

    header->nlmsg_len = NLMSG_LENGTH(sizeof(*family));
    header->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    family->nfgen_family = AF_UNSPEC;
    family->version = NFNETLINK_V0;
    family->res_id = htons(queue);
    add_attribute(header, NFQA_CFG_PARAMS, &params, sizeof(params));
    return send_message(fd, header);
}

static int send_verdict(int fd, uint32_t packet_id) {
    char buffer[NLMSG_SPACE(sizeof(struct nfgenmsg)) + NLA_ALIGN(sizeof(struct nlattr)) +
                sizeof(struct nfqnl_msg_verdict_hdr)] = {0};
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    struct nfgenmsg *family = (struct nfgenmsg *)NLMSG_DATA(header);
    struct nfqnl_msg_verdict_hdr message = {
        .verdict = htonl(verdict),
        .id = htonl(packet_id),
    };

    header->nlmsg_len = NLMSG_LENGTH(sizeof(*family));
    header->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
    header->nlmsg_flags = NLM_F_REQUEST;
    family->nfgen_family = AF_UNSPEC;
    family->version = NFNETLINK_V0;
    family->res_id = htons(queue_number);
    add_attribute(header, NFQA_VERDICT_HDR, &message, sizeof(message));
    return send_message(fd, header);
}

static void process_packet(int fd, const struct nlmsghdr *header) {
    const struct nfgenmsg *family = (const struct nfgenmsg *)NLMSG_DATA(header);
    size_t remaining = header->nlmsg_len - NLMSG_LENGTH(sizeof(*family));
    const struct nlattr *attribute = (const struct nlattr *)((const char *)family + sizeof(*family));

    while (remaining >= sizeof(*attribute) && attribute->nla_len >= sizeof(*attribute) &&
           attribute->nla_len <= remaining) {
        if (attribute->nla_type == NFQA_PACKET_HDR &&
            attribute->nla_len >= sizeof(*attribute) + sizeof(struct nfqnl_msg_packet_hdr)) {
            const struct nfqnl_msg_packet_hdr *packet = NLA_DATA(attribute);
            if (send_verdict(fd, ntohl(packet->packet_id)) < 0) {
                perror("NFQUEUE verdict");
                keep_running = 0;
                return;
            }
            if (verdict == NF_DROP) {
                dropped++;
            } else {
                accepted++;
            }
            printf("accepted=%llu dropped=%llu\n",
                   (unsigned long long)accepted, (unsigned long long)dropped);
            fflush(stdout);
            return;
        }
        size_t aligned = NLA_ALIGN(attribute->nla_len);
        if (aligned > remaining) {
            return;
        }
        remaining -= aligned;
        attribute = (const struct nlattr *)((const char *)attribute + aligned);
    }
}

static int parse_arguments(int argc, char **argv) {
    if (argc != 5 || strcmp(argv[1], "--queue") != 0 || strcmp(argv[3], "--mode") != 0) {
        fprintf(stderr, "usage: %s --queue NUMBER --mode accept|drop\n", argv[0]);
        return -1;
    }
    char *end = NULL;
    unsigned long parsed = strtoul(argv[2], &end, 10);
    if (!end || *end != '\0' || parsed > 65535) {
        fprintf(stderr, "invalid queue number\n");
        return -1;
    }
    queue_number = (unsigned short)parsed;
    if (strcmp(argv[4], "accept") == 0) {
        verdict = NF_ACCEPT;
    } else if (strcmp(argv[4], "drop") == 0) {
        verdict = NF_DROP;
    } else {
        fprintf(stderr, "invalid mode\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (parse_arguments(argc, argv) != 0) {
        return 2;
    }
    signal(SIGINT, stop_consumer);
    signal(SIGTERM, stop_consumer);
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) {
        perror("NFQUEUE socket");
        return 1;
    }
    if (configure_queue(fd, queue_number, NFQNL_CFG_CMD_BIND) < 0 || set_copy_mode(fd, queue_number) < 0) {
        perror("NFQUEUE configuration");
        close(fd);
        return 1;
    }
    while (keep_running) {
        char buffer[BUFFER_SIZE];
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("NFQUEUE receive");
            close(fd);
            return 1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned int)received);
             header = NLMSG_NEXT(header, received)) {
            if (header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
                process_packet(fd, header);
            }
        }
    }
    (void)configure_queue(fd, queue_number, NFQNL_CFG_CMD_UNBIND);
    close(fd);
    return 0;
}
