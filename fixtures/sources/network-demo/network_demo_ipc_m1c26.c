/* m1c-26 target decision process. Native helper transports NFQUEUE only.
 * The historical network-demo and P0 consumer sources stay immutable.
 */
#define _POSIX_C_SOURCE 200809L
#define main p0_consumer_main
#include "../nfqueue/nfqueue_consumer.c"
#undef main
#include <fcntl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/un.h>

#define IPC_MAGIC 0x4b45454dU
#define IPC_PATH "/opt/etc/network-demo/transport.sock"
static const char *state_path;
static bool queue_ready;

static int load_mode(void) {
    char text[16] = {0};
    int fd = open(state_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t size = read(fd, text, sizeof(text));
    close(fd);
    if (size == 7 && memcmp(text, "accept\n", 7) == 0) verdict = NF_ACCEPT;
    else if (size == 5 && memcmp(text, "drop\n", 5) == 0) verdict = NF_DROP;
    else return -1;
    return 0;
}
static int save_mode(const char *mode) {
    char temporary[512];
    if (strlen(state_path) > sizeof(temporary) - 32) return -1;
    snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", state_path, (long)getpid());
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t length = strlen(mode);
    int ok = write(fd, mode, length) == (ssize_t)length &&
             write(fd, "\n", 1) == 1 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (ok) ok = rename(temporary, state_path) == 0;
    if (!ok) { unlink(temporary); return -1; }
    int directory = open("/opt/etc/network-demo", O_RDONLY | O_DIRECTORY);
    if (directory >= 0) { (void)fsync(directory); close(directory); }
    return load_mode();
}
static void respond(int client, int status, const char *type, const char *body) {
    char header[256];
    int size = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        status, status == 200 ? "OK" : status == 503 ? "Unavailable" : "Bad Request",
        type, strlen(body));
    if (size > 0 && (size_t)size < sizeof(header)) {
        (void)write(client, header, (size_t)size);
        (void)write(client, body, strlen(body));
    }
}
static void handle_http(int listener) {
    int client = accept(listener, NULL, NULL);
    if (client < 0) return;
    struct timeval deadline = {.tv_sec = 2};
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
    char request[512] = {0};
    ssize_t size = read(client, request, sizeof(request) - 1);
    if (size <= 0) { close(client); return; }
    char body[256];
    if (strncmp(request, "POST /api/mode HTTP/1.", 21) == 0) {
        const char *value = strstr(request, "\r\n\r\n");
        const char *length = strstr(request, "Content-Length: ");
        unsigned long expected = length ? strtoul(length + 16, NULL, 10) : 0;
        if (!value || !length || expected > 11 ||
            strlen(value + 4) != expected ||
            (strcmp(value + 4, "mode=accept") && strcmp(value + 4, "mode=drop")) ||
            save_mode(value + 9) != 0) {
            respond(client, 400, "text/plain", "invalid mode\n");
            close(client); return;
        }
    } else if (strncmp(request, "GET /health HTTP/1.", 19) == 0) {
        respond(client, queue_ready ? 200 : 503, "text/plain",
                queue_ready ? "network-demo-ready\n" : "queue-unavailable\n");
        close(client); return;
    } else if (strncmp(request, "GET / HTTP/1.", 13) == 0) {
        respond(client, 200, "text/html",
                "<title>KEEMU network-demo IPC</title><form action='/api/mode' method='post'>"
                "<button name='mode' value='accept'>ACCEPT</button>"
                "<button name='mode' value='drop'>DROP</button></form>\n");
        close(client); return;
    } else if (strncmp(request, "GET /api/state HTTP/1.", 21) != 0) {
        respond(client, 400, "text/plain", "unknown endpoint\n");
        close(client); return;
    }
    if (load_mode() != 0) respond(client, 503, "text/plain", "mode unavailable\n");
    else {
        snprintf(body, sizeof(body),
            "{\"mode\":\"%s\",\"queue_ready\":%s,\"accepted\":%llu,\"dropped\":%llu}\n",
            verdict == NF_ACCEPT ? "accept" : "drop", queue_ready ? "true" : "false",
            (unsigned long long)accepted, (unsigned long long)dropped);
        respond(client, 200, "application/json", body);
    }
    close(client);
}
static int listen_api(const char *ip) {
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(9090)};
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(fd, 8) != 0) {
        close(fd); return -1;
    }
    return fd;
}

struct ipc_request {
    uint32_t magic, id, source, destination;
    uint16_t destination_port, reserved;
};
struct ipc_response {
    uint32_t magic, id, decision;
};

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

static void handle_ipc(int listener, uint32_t source, uint32_t destination) {
    int client = accept(listener, NULL, NULL);
    if (client < 0) return;
    struct timeval deadline = {.tv_sec = 2};
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
    (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));
    struct ipc_request request;
    if (receive_all(client, &request, sizeof(request)) != 0 ||
        ntohl(request.magic) != IPC_MAGIC || request.reserved != 0) {
        close(client);
        return;
    }
    struct ipc_response response = {
        .magic = htonl(IPC_MAGIC), .id = request.id, .decision = htonl(NF_DROP)
    };
    if (request.id == 0) {
        /* READY is sent only by the native adapter after queue ACKs. */
        queue_ready = true;
    } else if (queue_ready && request.source == source &&
               request.destination == destination &&
               request.destination_port == htons(8080) && load_mode() == 0) {
        response.decision = htonl(verdict);
        /* Counts decisions returned to transport, not kernel acknowledgements. */
        if (write(client, &response, sizeof(response)) == sizeof(response)) {
            if (verdict == NF_ACCEPT) accepted++;
            else dropped++;
            printf("target accepted=%llu dropped=%llu id=%u\n",
                   (unsigned long long)accepted, (unsigned long long)dropped,
                   ntohl(request.id));
            fflush(stdout);
        }
        close(client);
        return;
    }
    (void)write(client, &response, sizeof(response));
    close(client);
}

int main(int argc, char **argv) {
    /* --bind IP --client IP --server IP --state PATH */
    if (argc != 9 || strcmp(argv[1], "--bind") || strcmp(argv[3], "--client") ||
        strcmp(argv[5], "--server") || strcmp(argv[7], "--state")) return 2;
    struct in_addr bind_ip, client_ip, server_ip;
    if (inet_pton(AF_INET, argv[2], &bind_ip) != 1 ||
        inet_pton(AF_INET, argv[4], &client_ip) != 1 ||
        inet_pton(AF_INET, argv[6], &server_ip) != 1) return 2;
    state_path = argv[8];
    if (load_mode() != 0) return 2;
    signal(SIGINT, stop_consumer);
    signal(SIGTERM, stop_consumer);
    (void)unlink(IPC_PATH);
    int ipc = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (ipc < 0 || strlen(IPC_PATH) >= sizeof(address.sun_path)) return 1;
    strcpy(address.sun_path, IPC_PATH);
    if (bind(ipc, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(IPC_PATH, 0600) != 0 || listen(ipc, 8) != 0) {
        close(ipc);
        (void)unlink(IPC_PATH);
        return 1;
    }
    int api = listen_api(argv[2]);
    if (api < 0) {
        close(ipc);
        (void)unlink(IPC_PATH);
        return 1;
    }
    while (keep_running) {
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(api, &ready);
        FD_SET(ipc, &ready);
        int maximum = api > ipc ? api : ipc;
        if (select(maximum + 1, &ready, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (FD_ISSET(ipc, &ready)) handle_ipc(ipc, client_ip.s_addr, server_ip.s_addr);
        if (FD_ISSET(api, &ready)) handle_http(api);
    }
    close(api);
    close(ipc);
    (void)unlink(IPC_PATH);
    return 0;
}
