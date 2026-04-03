/**
 * TCP transport for the virtual HWP device.
 *
 * Replaces USB CDC transport from ESP32 firmware with POSIX sockets.
 * Semantically identical to serial: ordered byte stream with HWP framing.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "hwp.h"

/** Create a listening TCP socket on the given port. Returns server fd or -1. */
int tcp_listen(uint16_t port);

/** Accept a client connection. Sets TCP_NODELAY. Returns client fd or -1. */
int tcp_accept(int server_fd);

/** Send all bytes (blocking). Returns 0 on success, -1 on error. */
int tcp_send(int fd, const uint8_t *data, size_t len);

/** Read bytes and feed into HWP parser until a complete frame is ready.
 *  Returns HWP_FEED_FRAME_READY on success, HWP_FEED_CRC_ERROR on CRC,
 *  or HWP_FEED_INCOMPLETE on connection close / error. */
HwpFeedResult tcp_recv_frame(int fd, HwpParser *parser);

/** Close a socket. */
void tcp_close(int fd);
