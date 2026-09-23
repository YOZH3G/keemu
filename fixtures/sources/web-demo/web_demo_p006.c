#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUEST_CAPACITY 1024
#define RESPONSE_CAPACITY 1024
#define STATE_CAPACITY 65
#define UDP_CAPACITY 512

static volatile sig_atomic_t keep_running = 1;

static void stop_server(int signal_number) {
    (void)signal_number;
    keep_running = 0;
}

static int make_socket(int type, unsigned short port) {
    int fd = socket(AF_INET, type, 0);
    int enabled = 1;
    struct sockaddr_in address = {0};

    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    if (type == SOCK_STREAM && listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool valid_state(const char *value) {
    size_t length = strlen(value);
    if (length == 0 || length >= STATE_CAPACITY) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        unsigned char character = (unsigned char)value[index];
        if (!(isalnum(character) || character == '-' || character == '_')) {
            return false;
        }
    }
    return true;
}

static int read_state(const char *path, char state[STATE_CAPACITY]) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return -1;
    }
    if (fgets(state, STATE_CAPACITY, file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);
    state[strcspn(state, "\r\n")] = '\0';
    return valid_state(state) ? 0 : -1;
}

static int write_state(const char *path, const char *state) {
    FILE *file;
    if (!valid_state(state)) {
        return -1;
    }
    file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }
    if (fprintf(file, "%s\n", state) < 0 || fclose(file) != 0) {
        return -1;
    }
    return 0;
}

static void http_response(int client, int status, const char *body) {
    char response[RESPONSE_CAPACITY];
    const char *reason = status == 200 ? "OK" : "Bad Request";
    int length = snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n"
        "Connection: close\r\n\r\n%s",
        status,
        reason,
        strlen(body),
        body
    );
    if (length > 0 && (size_t)length < sizeof(response)) {
        (void)write(client, response, (size_t)length);
    }
}

static void handle_http(int listener, const char *state_path) {
    int client = accept(listener, NULL, NULL);
    char request[REQUEST_CAPACITY] = {0};
    char state[STATE_CAPACITY] = {0};
    char body[RESPONSE_CAPACITY];

    if (client < 0) {
        return;
    }
    (void)read(client, request, sizeof(request) - 1);
    if (strncmp(request, "POST /state?value=", 18) == 0) {
        char *value = request + 18;
        char *end = strchr(value, ' ');
        if (end == NULL) {
            http_response(client, 400, "bad-request\n");
            close(client);
            return;
        }
        *end = '\0';
        if (write_state(state_path, value) != 0) {
            http_response(client, 400, "bad-state\n");
            close(client);
            return;
        }
    } else if (strncmp(request, "GET /health ", 12) != 0) {
        http_response(client, 400, "bad-request\n");
        close(client);
        return;
    }
    if (read_state(state_path, state) != 0) {
        http_response(client, 400, "state-unavailable\n");
    } else {
        int length = snprintf(body, sizeof(body), "keemu-web-demo\nstate=%s\n", state);
        if (length > 0 && (size_t)length < sizeof(body)) {
            http_response(client, 200, body);
        } else {
            http_response(client, 400, "state-too-large\n");
        }
    }
    close(client);
}

static void handle_udp(int listener) {
    char request[UDP_CAPACITY];
    char response[UDP_CAPACITY + 16];
    struct sockaddr_in peer = {0};
    socklen_t peer_length = sizeof(peer);
    ssize_t length = recvfrom(
        listener,
        request,
        sizeof(request),
        0,
        (struct sockaddr *)&peer,
        &peer_length
    );
    if (length < 0) {
        return;
    }
    int response_length = snprintf(
        response,
        sizeof(response),
        "keemu-udp:%.*s",
        (int)length,
        request
    );
    if (response_length > 0 && (size_t)response_length < sizeof(response)) {
        (void)sendto(
            listener,
            response,
            (size_t)response_length,
            0,
            (const struct sockaddr *)&peer,
            peer_length
        );
    }
}

static int parse_port(const char *value, unsigned short *port) {
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (end == NULL || *end != '\0' || parsed == 0 || parsed > 65535) {
        return -1;
    }
    *port = (unsigned short)parsed;
    return 0;
}

int main(int argc, char **argv) {
    unsigned short http_port = 8080;
    unsigned short udp_port = 8081;
    const char *state_path = "/opt/etc/web-demo/state.txt";
    int http_listener;
    int udp_listener;

    if (argc == 4) {
        if (parse_port(argv[1], &http_port) != 0 || parse_port(argv[2], &udp_port) != 0) {
            fprintf(stderr, "usage: %s [http-port udp-port state-path]\n", argv[0]);
            return 2;
        }
        state_path = argv[3];
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [http-port udp-port state-path]\n", argv[0]);
        return 2;
    }
    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    http_listener = make_socket(SOCK_STREAM, http_port);
    udp_listener = make_socket(SOCK_DGRAM, udp_port);
    if (http_listener < 0 || udp_listener < 0) {
        perror("web-demo listener");
        if (http_listener >= 0) {
            close(http_listener);
        }
        if (udp_listener >= 0) {
            close(udp_listener);
        }
        return 1;
    }
    while (keep_running) {
        fd_set readable;
        int maximum = http_listener > udp_listener ? http_listener : udp_listener;
        FD_ZERO(&readable);
        FD_SET(http_listener, &readable);
        FD_SET(udp_listener, &readable);
        if (select(maximum + 1, &readable, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("web-demo select");
            break;
        }
        if (FD_ISSET(http_listener, &readable)) {
            handle_http(http_listener, state_path);
        }
        if (FD_ISSET(udp_listener, &readable)) {
            handle_udp(udp_listener);
        }
    }
    close(http_listener);
    close(udp_listener);
    return 0;
}
