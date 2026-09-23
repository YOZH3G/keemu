#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RESPONSE_CAPACITY 1024

static volatile sig_atomic_t keep_running = 1;

static void stop_server(int signal_number) {
    (void)signal_number;
    keep_running = 0;
}

static int make_listener(unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int enabled = 1;
    struct sockaddr_in address = {0};

    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void respond(int client) {
    char request[512] = {0};
    const char *body = "keemu-web-demo\n";
    char response[RESPONSE_CAPACITY];
    ssize_t ignored = read(client, request, sizeof(request) - 1);
    (void)ignored;
    int length = snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n"
        "Connection: close\r\n\r\n%s",
        strlen(body),
        body
    );
    if (length > 0 && (size_t)length < sizeof(response)) {
        (void)write(client, response, (size_t)length);
    }
}

int main(int argc, char **argv) {
    unsigned short port = 8080;
    if (argc == 2) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 10);
        if (!end || *end != '\0' || parsed == 0 || parsed > 65535) {
            fprintf(stderr, "usage: %s [port]\n", argv[0]);
            return 2;
        }
        port = (unsigned short)parsed;
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        return 2;
    }

    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    int listener = make_listener(port);
    if (listener < 0) {
        perror("web-demo listener");
        return 1;
    }
    while (keep_running) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("web-demo accept");
            close(listener);
            return 1;
        }
        respond(client);
        close(client);
    }
    close(listener);
    return 0;
}
