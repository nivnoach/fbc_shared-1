/*
 * 'udp_request_handler.h - radius_http_proxy'
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

#ifndef UDP_REQUEST_HANDLER_H
#define UDP_REQUEST_HANDLER_H

#include <ev.h>
#include <stdint.h>

typedef struct _udp_request_handler {
  int sock;
  struct ev_loop* loop;
  struct ev_io io;
} udp_request_handler_t;

typedef void (*udp_callback_t)(struct ev_loop*, struct ev_io*, int);

/*
 * Initialzie UDP request handler
 * evbase - libevent event base
 * port - port to listen
 * cb - event callback to call when socket is ready for getting data.
 * context - context to be passed on callback, Caller need to make sure for
 *   deallocation
 */
udp_request_handler_t* init_udp_request_handler(
    struct ev_loop* loop,
    uint16_t port,
    udp_callback_t cb,
    void* context);

/*
 * deallocates UDP request handler.
 */
void free_udp_request_handler(udp_request_handler_t* handler);

#endif
