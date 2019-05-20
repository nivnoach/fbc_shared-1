/*
 * 'http2_request_handler.h' - radius_http_proxy
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

#ifndef HTTP2_REQUEST_HANDLER_H
#define HTTP2_REQUEST_HANDLER_H

#include <curl/curl.h>
#include <ev.h>

#define HTTP2_RH_ERROR -1
#define HTTP2_RH_SUCCESS 0

/* Global information, common to all connections */
typedef void (*on_response_cb_t)(
    struct curl_slist* headers,
    char* data,
    size_t len,
    short is_stream,
    void* context);

typedef void (*http2_request_context_free_t)(void* context);

typedef struct _http2_response {
  char* body;
  size_t len;
  struct curl_slist* headers;
  short is_stream;
  on_response_cb_t response_cb;
  size_t content_len;
  long status_code;
} http2_response_t;

typedef struct _http2_request_handler {
  struct ev_loop* loop;
  struct ev_timer timer_event;
  CURLM* multi;
  int still_running;
  FILE* input;
} http2_request_handler_t;

/* Information associated with a specific easy handle */
typedef struct _http2_request {
  CURL* easy;
  char* url;
  char error[CURL_ERROR_SIZE];
  http2_request_handler_t* request_handler;
  http2_response_t* response;
  struct curl_slist* headers;
  char* data;
  void* context;
  http2_request_context_free_t free_request_context;
} http2_request_t;

/* Information associated with a specific socket */
typedef struct _sock_info {
  curl_socket_t sockfd;
  CURL* easy;
  int action;
  long timeout;
  struct ev_loop* loop;
  struct ev_io io;
  http2_request_handler_t* request_handler;
} sock_info_t;

http2_request_t* init_request(
    http2_request_handler_t* request_handler,
    on_response_cb_t response_cb,
    void* context,
    http2_request_context_free_t free_context);
int set_url(http2_request_t* request, char* url);
int set_post_data(http2_request_t* request, char* data);
int append_headers(http2_request_t* request, char* header);
int submit_request(http2_request_t* request);
int perform_request(http2_request_t* request);
void free_request(http2_request_t* request);

http2_request_handler_t* init_http2_request_handler(struct ev_loop* loop);
void free_http2_request_handler(http2_request_handler_t* request_handler);

#endif
