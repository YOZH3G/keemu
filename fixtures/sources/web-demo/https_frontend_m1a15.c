/* Independent AArch64 TLS frontend for the locked HTTP web-demo.
 * Usage: https-frontend PORT BACKEND_PORT SERVER_CERT_PEM SERVER_KEY_PEM
 * One bounded request per connection; no client authentication or generic proxying.
 * TLS trust and hostname verification belong to the client, not this server.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define REQUEST_LIMIT 2048
#define RESPONSE_LIMIT 2048
static volatile sig_atomic_t running = 1;
static void stop_handler(int signum) { (void)signum; running = 0; }

static int port_from(const char *text) {
    char *end = NULL;
    unsigned long port;
    if (*text == '\0' || *text == '-' || *text == '+') return -1;
    errno = 0;
    port = strtoul(text, &end, 10);
    if (errno || *end || port < 1 || port > 65535) return -1;
    return (int)port;
}

static void deadlines(int fd) {
    struct timeval limit = {.tv_sec = 3, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
}

static bool allowed_line(const char *line, size_t len) {
    const char *end = memchr(line, '\n', len);
    size_t n;
    if (!end || end == line || end[-1] != '\r') return false;
    n = (size_t)(end - line) - 1;
    if (n == strlen("GET /health HTTP/1.1") &&
        memcmp(line, "GET /health HTTP/1.1", n) == 0) return true;
    if (n == strlen("GET /health HTTP/1.0") &&
        memcmp(line, "GET /health HTTP/1.0", n) == 0) return true;
    const char *prefix = "POST /state?value=";
    size_t p = strlen(prefix);
    if (n < p + 10 || memcmp(line, prefix, p) != 0) return false;
    const char *space = memchr(line + p, ' ', n - p);
    if (!space || space == line + p || (size_t)(space - (line + p)) > 64) return false;
    size_t suffix = n - (size_t)(space - line);
    if (suffix != strlen(" HTTP/1.1") ||
        (memcmp(space, " HTTP/1.1", suffix) != 0 &&
         memcmp(space, " HTTP/1.0", suffix) != 0)) return false;
    for (const char *c = line + p; c < space; ++c)
        if (!(('a' <= *c && *c <= 'z') || ('A' <= *c && *c <= 'Z') ||
              ('0' <= *c && *c <= '9') || *c == '-' || *c == '_')) return false;
    return true;
}

static void serve(SSL_CTX *ctx, int client, int backend_port) {
    SSL *tls = SSL_new(ctx);
    char request[REQUEST_LIMIT + 1];
    char response[RESPONSE_LIMIT];
    int upstream = -1;
    if (!tls) return;
    deadlines(client);
    if (SSL_set_fd(tls, client) != 1 || SSL_accept(tls) != 1) goto done;
    int got = SSL_read(tls, request, REQUEST_LIMIT);
    if (got <= 0) goto done;
    request[got] = '\0';
    /* Reject embedded NUL, incomplete/oversized request lines and other routes. */
    if (memchr(request, '\0', (size_t)got) || !allowed_line(request, (size_t)got)) goto done;
    char *line_end = strstr(request, "\r\n");
    if (!line_end) goto done;
    size_t line_bytes = (size_t)(line_end - request) + 2;
    upstream = socket(AF_INET, SOCK_STREAM, 0);
    if (upstream < 0) goto done;
    deadlines(upstream);
    struct sockaddr_in addr = {.sin_family = AF_INET};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)backend_port);
    if (connect(upstream, (struct sockaddr *)&addr, sizeof(addr)) != 0) goto done;
    /* Only request line crosses the TLS boundary; backend ignores other headers. */
    static const char headers[] = "Host: localhost\r\nConnection: close\r\n\r\n";
    if (send(upstream, request, line_bytes, 0) != (ssize_t)line_bytes ||
        send(upstream, headers, sizeof(headers) - 1, 0) != (ssize_t)(sizeof(headers) - 1))
        goto done;
    ssize_t bytes = recv(upstream, response, sizeof(response), 0);
    if (bytes <= 0) goto done;
    for (ssize_t sent = 0; sent < bytes;) {
        int n = SSL_write(tls, response + sent, (int)(bytes - sent));
        if (n <= 0) break;
        sent += n;
    }
done:
    if (upstream >= 0) close(upstream);
    /* No blocking close_notify: peer may not complete shutdown. */
    SSL_free(tls);
}

int main(int argc, char **argv) {
    int listener = -1;
    if (argc != 5) {
        fprintf(stderr, "usage: %s PORT BACKEND_PORT SERVER_CERT_PEM SERVER_KEY_PEM\n", argv[0]);
        return 2;
    }
    int port = port_from(argv[1]), backend_port = port_from(argv[2]);
    if (port < 0 || backend_port < 0 || port == backend_port) return 2;
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    signal(SIGPIPE, SIG_IGN);
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) goto fail;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_use_certificate_chain_file(ctx, argv[3]) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) goto fail;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) goto fail;
    int reuse = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY),
                               .sin_port = htons((unsigned short)port)};
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listener, 8) != 0)
        goto fail;
    while (running) {
        fd_set ready;
        struct timeval tick = {.tv_sec = 1};
        FD_ZERO(&ready);
        FD_SET(listener, &ready);
        int count = select(listener + 1, &ready, NULL, NULL, &tick);
        if (count > 0) {
            int client = accept(listener, NULL, NULL);
            if (client >= 0) { serve(ctx, client, backend_port); close(client); }
        } else if (count < 0 && errno != EINTR) goto fail;
    }
    close(listener);
    SSL_CTX_free(ctx);
    return 0;
fail:
    ERR_print_errors_fp(stderr);
    perror("https-frontend");
    if (listener >= 0) close(listener);
    SSL_CTX_free(ctx);
    return 1;
}
