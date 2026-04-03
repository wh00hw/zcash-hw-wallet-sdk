#include "tcp_transport.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

int tcp_listen(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port),
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, 1) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

int tcp_accept(int server_fd)
{
    int fd = accept(server_fd, NULL, NULL);
    if (fd < 0) { perror("accept"); return -1; }

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    return fd;
}

int tcp_send(int fd, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, data + sent, len - sent);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

HwpFeedResult tcp_recv_frame(int fd, HwpParser *parser)
{
    hwp_parser_init(parser);

    for (;;) {
        uint8_t byte;
        ssize_t n = read(fd, &byte, 1);
        if (n <= 0) return HWP_FEED_INCOMPLETE; /* connection closed */

        HwpFeedResult res = hwp_parser_feed(parser, byte);
        if (res == HWP_FEED_FRAME_READY || res == HWP_FEED_CRC_ERROR)
            return res;
        /* HWP_FEED_INCOMPLETE / HWP_FEED_OVERFLOW: keep reading */
    }
}

void tcp_close(int fd)
{
    close(fd);
}
