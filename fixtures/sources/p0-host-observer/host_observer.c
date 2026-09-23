#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define HTTP_CAPACITY 4096
#define UDP_CAPACITY 512

static int parse_port(const char *value, unsigned short *port) {
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (end == NULL || *end != '\0' || parsed == 0 || parsed > 65535) {
        return -1;
    }
    *port = (unsigned short)parsed;
    return 0;
}

static int make_address(struct sockaddr_in *address, unsigned short port) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    return inet_pton(AF_INET, "127.0.0.1", &address->sin_addr) == 1 ? 0 : -1;
}

static int check_http(unsigned short port, const char *state) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    const char request[] =
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    char response[HTTP_CAPACITY] = {0};
    char expected[256];
    size_t used = 0;

    if (fd < 0 || make_address(&address, port) != 0 ||
        connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        write(fd, request, sizeof(request) - 1) != (ssize_t)(sizeof(request) - 1)) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    while (used < sizeof(response) - 1) {
        ssize_t read_count = read(fd, response + used, sizeof(response) - 1 - used);
        if (read_count < 0) {
            close(fd);
            return -1;
        }
        if (read_count == 0) {
            break;
        }
        used += (size_t)read_count;
    }
    close(fd);
    if (strncmp(response, "HTTP/1.1 200 ", 13) != 0) {
        return -1;
    }
    char *body = strstr(response, "\r\n\r\n");
    if (body == NULL) {
        return -1;
    }
    body += 4;
    int expected_length = snprintf(
        expected, sizeof(expected), "keemu-web-demo\nstate=%s\n", state
    );
    if (expected_length <= 0 || (size_t)expected_length >= sizeof(expected)) {
        return -1;
    }
    return strcmp(body, expected) == 0 ? 0 : -1;
}

static int check_udp(unsigned short port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address;
    const char payload[] = "p006-host-observer";
    const char expected[] = "keemu-udp:p006-host-observer";
    char response[UDP_CAPACITY] = {0};
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};

    if (fd < 0 || make_address(&address, port) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        sendto(fd, payload, sizeof(payload) - 1, 0,
               (const struct sockaddr *)&address, sizeof(address)) !=
            (ssize_t)(sizeof(payload) - 1)) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    ssize_t received = recvfrom(fd, response, sizeof(response) - 1, 0, NULL, NULL);
    close(fd);
    if (received < 0) {
        return -1;
    }
    response[received] = '\0';
    return strcmp(response, expected) == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    unsigned short http_port;
    unsigned short udp_port;

    if (argc != 4 || parse_port(argv[1], &http_port) != 0 ||
        parse_port(argv[2], &udp_port) != 0) {
        fprintf(stderr, "usage: %s HTTP_PORT UDP_PORT EXPECTED_STATE\n", argv[0]);
        return 2;
    }
    if (check_http(http_port, argv[3]) != 0) {
        fprintf(stderr, "host HTTP observation failed: %s\n", strerror(errno));
        return 1;
    }
    if (check_udp(udp_port) != 0) {
        fprintf(stderr, "host UDP observation failed: %s\n", strerror(errno));
        return 1;
    }
    printf("host-observer HTTP_OK UDP_OK state=%s\n", argv[3]);
    return 0;
}
