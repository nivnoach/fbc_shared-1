/*
 * 'coa_sse_handle.h' - radius_http_proxy
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

#ifndef COA_SSE_HANDLER_H
#define COA_SSE_HANDLER_H

#include <arpa/inet.h>
#include <ev.h>
#include "http2_request_handler.h"

struct coa_event_timer {
  struct ev_timer expire;
  void* data;
};

typedef struct {
  http2_request_handler_t* http_handler;
  http2_request_t* http_request;
  struct ev_loop* loop;
  struct coa_event_timer timer_event;
  ev_tstamp sse_timeout;
  struct ev_io coa_ack_event;
  struct sockaddr_in sin;
  int coa_fd;
} coa_sse_handler_t;

int subscribe_to_coa_requests(coa_sse_handler_t* coa_handler);
coa_sse_handler_t* init_coa_handler(
    struct ev_loop* loop,
    http2_request_handler_t* http_handler);
void free_coa_handler(coa_sse_handler_t* coa_handler);

#endif
