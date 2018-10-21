/*
 * 'udp_request_handler.c - radius_http_proxy'
 *
 * Copyright (c) 2018-present, Facebook, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "udp_request_handler.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "config_parser.h"
#include "utils/utils.h"

udp_request_handler_t* init_udp_request_handler(
    struct ev_loop* loop,
    uint16_t port,
    udp_callback_t cb,
    void* context) {
  int sock;
  struct sockaddr_in sin;
  udp_request_handler_t* res = NULL;

  if (loop == NULL) {
    RAD_PROXY_LOG_ERR("Receivied NULL parameter");
    return NULL;
  }
  RAD_PROXY_LOG_TRACE("Initalizing UDP handler on port %u", port);

  memset(&sin, 0, sizeof(sin));
  sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = conf_opts.req_listen_ip.s_addr;
  sin.sin_port = htons(port);

  if (bind(sock, (struct sockaddr*)&sin, sizeof(sin))) {
    RAD_PROXY_LOG_ERR("Cannot bind to port %u", port);
    goto error_close_sock;
  }

  res = (udp_request_handler_t*)malloc(sizeof(udp_request_handler_t));
  GO_TO_ERR_ON_MALLOC_FAIL(res, error_close_sock);

  res->sock = sock;
  res->loop = loop;

  ev_io_init(&res->io, cb, sock, EV_READ);
  res->io.data = context;
  ev_io_start(loop, &res->io);

  return res;

error_close_sock:
  close(sock);
  return NULL;
}

void free_udp_request_handler(udp_request_handler_t* handler) {
  if (handler == NULL) {
    return;
  }
  ev_io_stop(handler->loop, &handler->io);
  close(handler->sock);
  free(handler);
}
