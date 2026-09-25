/* Network-demo extends, rather than replaces, the P0 target NFQUEUE consumer.
 * Historical P0 source/hash are immutable. Its queue framing, verdict sender and
 * counters are compiled here in the same translation unit without a second path.
 */
#define _POSIX_C_SOURCE 200809L
#define main p0_consumer_main
#include "../nfqueue/nfqueue_consumer.c"
#undef main

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/stat.h>

#define HTTP_CAP 4096
static const char *state_path;
static bool queue_ready;
static bool api_only;

static int load_mode(void) {
    char text[16] = {0};
    int fd = open(state_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    ssize_t size = read(fd, text, sizeof(text));
    close(fd);
    if (size == 7 && memcmp(text, "accept\n", 7) == 0) {
        verdict = NF_ACCEPT;
    } else if (size == 5 && memcmp(text, "drop\n", 5) == 0) {
        verdict = NF_DROP;
    } else {
        return -1;
    }
    return 0;
}

static int save_mode(const char *mode) {
    char temporary[512];
    if (strlen(state_path) > sizeof(temporary) - 32) {
        return -1;
    }
    (void)snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", state_path, (long)getpid());
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    size_t length = strlen(mode);
    int success = write(fd, mode, length) == (ssize_t)length &&
                  write(fd, "\n", 1) == 1 && fsync(fd) == 0;
    if (close(fd) != 0) {
        success = 0;
    }
    if (success) {
        success = rename(temporary, state_path) == 0;
    }
    if (!success) {
        (void)unlink(temporary);
        return -1;
    }
    int directory = open("/opt/etc/network-demo", O_RDONLY | O_DIRECTORY);
    if (directory >= 0) {
        (void)fsync(directory);
        close(directory);
    }
    return load_mode();
}

static void respond(int client, int status, const char *type, const char *body) {
    char header[256];
    const char *reason = status == 200 ? "OK" : status == 503 ? "Unavailable" :
                         status == 405 ? "Method Not Allowed" : "Bad Request";
    int length = snprintf(header, sizeof(header),
                          "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                          "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                          status, reason, type, strlen(body));
    if (length > 0 && (size_t)length < sizeof(header)) {
        (void)write(client, header, (size_t)length);
        (void)write(client, body, strlen(body));
    }
}

static void handle_http(int listener) {
    int client = accept(listener, NULL, NULL);
    if (client < 0) {
        return;
    }
    struct timeval deadline = {.tv_sec = 2};
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
    char request[HTTP_CAP] = {0};
    ssize_t received = read(client, request, sizeof(request) - 1);
    if (received <= 0) {
        close(client);
        return;
    }
    const char *body = strstr(request, "\r\n\r\n");
    char state[256];
    if (strncmp(request, "GET /api/state HTTP/1.", 21) == 0 ||
        strncmp(request, "POST /api/mode HTTP/1.", 21) == 0) {
        bool post = request[0] == 'P';
        if (post) {
            /* Reject incomplete, oversized and ambiguous writes. No query-string writes. */
            const char *length = strstr(request, "Content-Length: ");
            char *end = NULL;
            unsigned long expected = length ? strtoul(length + 16, &end, 10) : 0;
            if (!body || !length || end == length + 16 ||
                strncmp(end, "\r\n", 2) != 0 || expected > 32 ||
                strstr(end + 2, "Content-Length: ") ||
                strstr(request, "Transfer-Encoding:") ||
                strstr(request, "transfer-encoding:")) {
                respond(client, 400, "text/plain", "invalid mode\n");
                close(client);
                return;
            }
            while (strlen(body + 4) < expected && received < HTTP_CAP - 1) {
                ssize_t more = read(client, request + received, HTTP_CAP - 1 - received);
                if (more <= 0) {
                    break;
                }
                received += more;
                request[received] = '\0';
            }
            if (strlen(body + 4) != expected || expected > 11 ||
                (strcmp(body + 4, "mode=accept") != 0 &&
                 strcmp(body + 4, "mode=drop") != 0) ||
                save_mode(body + 9) != 0) {
                respond(client, 400, "text/plain", "mode not saved\n");
                close(client);
                return;
            }
        }
        if (load_mode() != 0) {
            respond(client, 503, "text/plain", "mode unavailable\n");
        } else {
            (void)snprintf(state, sizeof(state),
                           "{\"mode\":\"%s\",\"queue_ready\":%s,"
                           "\"accepted\":%llu,\"dropped\":%llu}\n",
                           verdict == NF_ACCEPT ? "accept" : "drop",
                           queue_ready ? "true" : "false",
                           (unsigned long long)accepted, (unsigned long long)dropped);
            respond(client, 200, "application/json", state);
        }
    } else if (strncmp(request, "GET /health HTTP/1.", 19) == 0) {
        respond(client, queue_ready ? 200 : 503, "text/plain",
                queue_ready ? "network-demo-ready\n" : "queue-unavailable\n");
    } else if (strncmp(request, "GET / HTTP/1.", 13) == 0) {
        respond(client, 200, "text/html; charset=utf-8",
                "<!doctype html><title>KEEMU network-demo</title>"
                "<h1>Network-demo</h1><p>GET /api/state: mode, queue_ready, counters</p>"
                "<form action='/api/mode' method='post'>"
                "<button name='mode' value='accept'>ACCEPT</button>"
                "<button name='mode' value='drop'>DROP</button></form>\n");
    } else {
        respond(client, 400, "text/plain", "unknown endpoint\n");
    }
    close(client);
}

static int listen_api(const char *address, unsigned short port) {
    struct sockaddr_in bind_address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, address, &bind_address.sin_addr) != 1) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(fd, (const struct sockaddr *)&bind_address, sizeof(bind_address)) != 0 ||
        listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int confirm_queue(int fd) {
    struct timeval timeout = {.tv_sec = 2};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        return -1;
    }
    int acknowledgements = 0;
    while (acknowledgements < 2) {
        char buffer[BUFFER_SIZE];
        ssize_t size = recv(fd, buffer, sizeof(buffer), 0);
        if (size <= 0) {
            return -1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned int)size);
             header = NLMSG_NEXT(header, size)) {
            if (header->nlmsg_type != NLMSG_ERROR ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                return -1;
            }
            const struct nlmsgerr *error = NLMSG_DATA(header);
            if (error->error != 0) {
                errno = -error->error;
                return -1;
            }
            ++acknowledgements;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    /* API-only is an explicit diagnostic; never advertise a working packet path. */
    if ((argc != 9 && argc != 10) || strcmp(argv[1], "--queue") != 0 ||
        strcmp(argv[3], "--bind") != 0 || strcmp(argv[5], "--port") != 0 ||
        strcmp(argv[7], "--state") != 0 ||
        (argc == 10 && strcmp(argv[9], "--api-only") != 0)) {
        fprintf(stderr, "usage: network-demo --queue N --bind IPv4 --port N --state PATH [--api-only]\n");
        return 2;
    }
    char *end = NULL;
    unsigned long number = strtoul(argv[2], &end, 10);
    if (!argv[2][0] || *end || number > 65535) {
        return 2;
    }
    queue_number = (unsigned short)number;
    number = strtoul(argv[6], &end, 10);
    if (!argv[6][0] || *end || !number || number > 65535) {
        return 2;
    }
    state_path = argv[8];
    if (load_mode() != 0) {
        fprintf(stderr, "network-demo state missing or invalid\n");
        return 1;
    }
    api_only = argc == 10;
    signal(SIGINT, stop_consumer);
    signal(SIGTERM, stop_consumer);
    bool failed = false;
    int queue = -1;
    if (!api_only) {
        queue = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
        if (queue < 0 || configure_queue(queue, queue_number, NFQNL_CFG_CMD_BIND) < 0 ||
            set_copy_mode(queue, queue_number) < 0 || confirm_queue(queue) != 0) {
            perror("network-demo NFQUEUE");
            if (queue >= 0) {
                close(queue);
            }
            return 4;
        }
        queue_ready = true;
    }
    int api = listen_api(argv[4], (unsigned short)number);
    if (api < 0) {
        perror("network-demo API");
        if (queue >= 0) {
            (void)configure_queue(queue, queue_number, NFQNL_CFG_CMD_UNBIND);
            close(queue);
        }
        return 1;
    }
    while (keep_running) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(api, &readable);
        if (queue >= 0) {
            FD_SET(queue, &readable);
        }
        int maximum = api > queue ? api : queue;
        if (select(maximum + 1, &readable, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            failed = true;
            break;
        }
        if (FD_ISSET(api, &readable)) {
            handle_http(api);
        }
        if (queue >= 0 && FD_ISSET(queue, &readable)) {
            char buffer[BUFFER_SIZE];
            ssize_t size = recv(queue, buffer, sizeof(buffer), 0);
            if (size < 0 && errno == EINTR) {
                continue;
            }
            if (size <= 0) {
                failed = true;
                break;
            }
            for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
                 NLMSG_OK(header, (unsigned int)size);
                 header = NLMSG_NEXT(header, size)) {
                if (header->nlmsg_type == NLMSG_ERROR) {
                    const struct nlmsgerr *error = NLMSG_DATA(header);
                    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*error)) || error->error) {
                        failed = true;
                        keep_running = 0;
                        break;
                    }
                } else if (header->nlmsg_type ==
                           ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
                    if (load_mode() != 0) {
                        /* No ACCEPT on invalid state; stop rather than fake a verdict. */
                        failed = true;
                        keep_running = 0;
                        break;
                    }
                    process_packet(queue, header);
                    if (!keep_running) {
                        failed = true;
                    }
                }
            }
        }
    }
    close(api);
    if (queue >= 0) {
        (void)configure_queue(queue, queue_number, NFQNL_CFG_CMD_UNBIND);
        close(queue);
    }
    return failed ? 1 : 0;
}
