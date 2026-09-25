/* m1c-26 native NFQUEUE transport; NEVER chooses ACCEPT from local state.
 * The AArch64 network-demo IPC process selects each verdict and counts it.
 */
#define main p0_consumer_main
#include "../nfqueue/nfqueue_consumer.c"
#undef main
#include <sys/select.h>
#include <sys/un.h>
#include <time.h>

#define IPC_MAGIC 0x4b45454dU
#define IPC_PATH "/opt/etc/network-demo/transport.sock"
struct ipc_request {
    uint32_t magic, id, source, destination;
    uint16_t destination_port, reserved;
};
struct ipc_response {
    uint32_t magic, id, decision;
};
struct capture_header {
    uint32_t magic;
    uint16_t major, minor;
    int32_t timezone;
    uint32_t sigfigs, snaplen, network;
};
struct capture_record {
    uint32_t seconds, micros, captured, original;
};
static FILE *capture;
static unsigned int capture_count;
static void capture_packet(const struct nlmsghdr *header) {
    if (!capture || capture_count >= 64 ||
        header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg))) return;
    const struct nfgenmsg *family = NLMSG_DATA(header);
    size_t remaining = header->nlmsg_len - NLMSG_LENGTH(sizeof(*family));
    const struct nlattr *attribute = (const struct nlattr *)(family + 1);
    while (remaining >= sizeof(*attribute) && attribute->nla_len >= sizeof(*attribute) &&
           attribute->nla_len <= remaining) {
        if (attribute->nla_type == NFQA_PAYLOAD) {
            size_t size = attribute->nla_len - sizeof(*attribute);
            size_t copied = size < 256 ? size : 256;
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            struct capture_record record = {
                (uint32_t)now.tv_sec, (uint32_t)(now.tv_nsec / 1000),
                (uint32_t)copied, (uint32_t)size
            };
            if (fwrite(&record, sizeof(record), 1, capture) == 1 &&
                fwrite(NLA_DATA(attribute), 1, copied, capture) == copied) {
                fflush(capture);
                capture_count++;
            }
            return;
        }
        size_t step = NLA_ALIGN(attribute->nla_len);
        if (step > remaining) return;
        remaining -= step;
        attribute = (const struct nlattr *)((const char *)attribute + step);
    }
}

static int receive_all(int fd, void *data, size_t length) {
    unsigned char *cursor = data;
    while (length) {
        ssize_t size = read(fd, cursor, length);
        if (size <= 0) return -1;
        cursor += size;
        length -= (size_t)size;
    }
    return 0;
}
static int transmit(const struct ipc_request *request, uint32_t *choice) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval deadline = {.tv_sec = 2};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, IPC_PATH);
    struct ipc_response response;
    int ok = connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0 &&
             write(fd, request, sizeof(*request)) == sizeof(*request) &&
             receive_all(fd, &response, sizeof(response)) == 0 &&
             response.magic == htonl(IPC_MAGIC) && response.id == request->id;
    close(fd);
    if (!ok) return -1;
    *choice = ntohl(response.decision);
    return (*choice == NF_ACCEPT || *choice == NF_DROP) ? 0 : -1;
}
static int await_ack(int fd) {
    struct timeval deadline = {.tv_sec = 2};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
    for (int count = 0; count < 2;) {
        char buffer[BUFFER_SIZE];
        ssize_t size = recv(fd, buffer, sizeof(buffer), 0);
        if (size <= 0) return -1;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned int)size); header = NLMSG_NEXT(header, size)) {
            if (header->nlmsg_type != NLMSG_ERROR ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return -1;
            const struct nlmsgerr *error = NLMSG_DATA(header);
            if (error->error) { errno = -error->error; return -1; }
            count++;
        }
    }
    return 0;
}
static int parse_packet(const struct nlmsghdr *header, struct ipc_request *request) {
    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg))) return -1;
    const struct nfgenmsg *family = NLMSG_DATA(header);
    size_t remaining = header->nlmsg_len - NLMSG_LENGTH(sizeof(*family));
    const struct nlattr *attribute = (const struct nlattr *)(family + 1);
    uint32_t id = 0;
    const unsigned char *payload = NULL;
    size_t length = 0;
    while (remaining >= sizeof(*attribute) && attribute->nla_len >= sizeof(*attribute) &&
           attribute->nla_len <= remaining) {
        if (attribute->nla_type == NFQA_PACKET_HDR &&
            attribute->nla_len >= sizeof(*attribute) + sizeof(struct nfqnl_msg_packet_hdr)) {
            const struct nfqnl_msg_packet_hdr *packet = NLA_DATA(attribute);
            id = packet->packet_id;
        } else if (attribute->nla_type == NFQA_PAYLOAD) {
            payload = NLA_DATA(attribute);
            length = attribute->nla_len - sizeof(*attribute);
        }
        size_t step = NLA_ALIGN(attribute->nla_len);
        if (step > remaining) break;
        remaining -= step;
        attribute = (const struct nlattr *)((const char *)attribute + step);
    }
    if (!id) return -1;
    request->magic = htonl(IPC_MAGIC);
    request->id = id;
    request->reserved = 0;
    request->source = request->destination = 0;
    request->destination_port = 0;
    if (!payload || length < 24 || (payload[0] >> 4) != 4 || payload[9] != 6) return 0;
    size_t ip_header = (payload[0] & 15U) * 4U;
    if (ip_header < 20 || length < ip_header + 4) return 0;
    memcpy(&request->source, payload + 12, 4);
    memcpy(&request->destination, payload + 16, 4);
    memcpy(&request->destination_port, payload + ip_header + 2, 2);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--queue") || strcmp(argv[2], "42")) return 2;
    queue_number = 42;
    signal(SIGTERM, stop_consumer);
    signal(SIGINT, stop_consumer);
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0 || configure_queue(fd, queue_number, NFQNL_CFG_CMD_BIND) < 0 ||
        set_copy_mode(fd, queue_number) < 0 || await_ack(fd) < 0) {
        perror("transport queue startup");
        if (fd >= 0) close(fd);
        return 4;
    }
    struct timeval unlimited = {0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &unlimited, sizeof(unlimited));
    capture = fopen("/opt/etc/network-demo/packets.pcap", "wb");
    if (!capture) { close(fd); return 4; }
    struct capture_header pcap = {0xa1b2c3d4U, 2, 4, 0, 0, 256, 101};
    if (fwrite(&pcap, sizeof(pcap), 1, capture) != 1) {
        fclose(capture); close(fd); return 4;
    }
    struct ipc_request ready = {.magic = htonl(IPC_MAGIC)};
    uint32_t response;
    for (int attempt = 0; attempt < 20; attempt++) {
        if (transmit(&ready, &response) == 0) break;
        struct timespec pause = {.tv_nsec = 100000000};
        nanosleep(&pause, NULL);
        if (attempt == 19) { close(fd); return 4; }
    }
    printf("transport queue_ready=1\n");
    fflush(stdout);
    while (keep_running) {
        char buffer[BUFFER_SIZE];
        ssize_t size = recv(fd, buffer, sizeof(buffer), 0);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) break;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned int)size); header = NLMSG_NEXT(header, size)) {
            if (header->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) continue;
            struct ipc_request request;
            if (parse_packet(header, &request) < 0) continue;
            capture_packet(header);
            uint32_t chosen = NF_DROP;
            int target_ok = transmit(&request, &chosen) == 0;
            verdict = target_ok ? chosen : NF_DROP;
            if (send_verdict(fd, ntohl(request.id)) < 0) {
                perror("transport verdict");
                keep_running = 0;
                break;
            }
            if (verdict == NF_ACCEPT) accepted++;
            else dropped++;
            printf("transport accepted=%llu dropped=%llu id=%u target=%d\n",
                   (unsigned long long)accepted, (unsigned long long)dropped,
                   ntohl(request.id), target_ok);
            fflush(stdout);
        }
    }
    (void)configure_queue(fd, queue_number, NFQNL_CFG_CMD_UNBIND);
    close(fd);
    fclose(capture);
    return keep_running ? 1 : 0;
}
