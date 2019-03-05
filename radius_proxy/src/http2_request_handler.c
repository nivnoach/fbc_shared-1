/*
 * 'http2_request_handler.c' - radius_http_proxy
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

#include "http2_request_handler.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "utils/utils.h"

#define MSG_OUT stdout
#define CONTENT_LENGTH_HEADER "content-length:"

/* Update the event timer after curl_multi library calls */
static int multi_timer_cb(
    CURLM* multi,
    long timeout_ms,
    http2_request_handler_t* req_handler) {
  (void)multi; /* unused */

  if (req_handler == NULL) {
    RAD_PROXY_LOG_ERR("Request handler is null");
    return HTTP2_RH_ERROR;
  }

  ev_timer_stop(req_handler->loop, &req_handler->timer_event);
  if (timeout_ms >= 0) {
    ev_timer_set(&req_handler->timer_event, (ev_tstamp)timeout_ms / 1000., 0.);
    ev_timer_start(req_handler->loop, &req_handler->timer_event);
  }
  return 0;
}

/* Check for completed transfers, and remove their easy handles */
static void check_multi_info(http2_request_handler_t* request_handler) {
  char* eff_url;
  CURLMsg* msg;
  int msgs_left;
  http2_request_t* request;
  CURL* easy;

  if (request_handler == NULL) {
    RAD_PROXY_LOG_ERR("Request handler is null");
    return;
  }

  while ((msg = curl_multi_info_read(request_handler->multi, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      easy = msg->easy_handle;
      curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char**)&request);
      curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);
      free_request(request);
    }
  }
}

/* Called by libev when we get action on a multi socket */
static void
handle_multi_event(struct ev_loop* loop, struct ev_io* event, int revents) {
  http2_request_handler_t* request_handler =
      (http2_request_handler_t*)event->data;
  CURLMcode rc;

  if (request_handler == NULL) {
    RAD_PROXY_LOG_ERR("Received NULL parameter");
    return;
  }

  int action = (revents & EV_READ ? CURL_CSELECT_IN : 0) |
      (revents & EV_WRITE ? CURL_CSELECT_OUT : 0);

  rc = curl_multi_socket_action(
      request_handler->multi,
      event->fd,
      action,
      &request_handler->still_running);
  if (rc != CURLM_OK) {
    RAD_PROXY_LOG_ERR(
        "Cannot perform curl_multi_socket_action, error: %d", rc);
    return;
  }

  check_multi_info(request_handler);
  if (request_handler->still_running <= 0) {
    ev_timer_stop(loop, &request_handler->timer_event);
  }
}

/* Called by libevent when our timeout expires */
static void
timer_cb(struct ev_loop* loop, struct ev_timer* timer, int revents) {
  http2_request_handler_t* request_handler =
      (http2_request_handler_t*)timer->data;
  CURLMcode rc;

  if (request_handler == NULL) {
    RAD_PROXY_LOG_ERR("Request handler is null");
    return;
  }

  rc = curl_multi_socket_action(
      request_handler->multi,
      CURL_SOCKET_TIMEOUT,
      0,
      &request_handler->still_running);
  if (rc != CURLM_OK) {
    RAD_PROXY_LOG_ERR(
        "Cannot perform curl_multi_socket_action, error: %d", rc);
    return;
  }
  check_multi_info(request_handler);
}

/* Clean up the sock_info_t structure */
static void remsock(sock_info_t* sock_info) {
  if (sock_info) {
    ev_io_stop(sock_info->loop, &sock_info->io);
    free(sock_info);
  }
}

/* Assign information to a sock_info_t structure */
static int setsock(
    sock_info_t* sock_info,
    curl_socket_t sock,
    CURL* easy,
    int act,
    http2_request_handler_t* client) {
  int kind =
      (act & CURL_POLL_IN ? EV_READ : 0) | (act & CURL_POLL_OUT ? EV_WRITE : 0);

  sock_info->sockfd = sock;
  sock_info->action = act;
  sock_info->easy = easy;
  sock_info->io.data = client;

  ev_io_stop(sock_info->loop, &sock_info->io);
  ev_io_init(&sock_info->io, handle_multi_event, sock_info->sockfd, kind);
  ev_io_start(sock_info->loop, &sock_info->io);
  return HTTP2_RH_SUCCESS;
}

/* Initialize a new sock_info_t structure */
static int addsock(
    curl_socket_t sock,
    CURL* easy,
    int action,
    http2_request_handler_t* request_handler) {
  int code = 0;
  sock_info_t* sock_info = calloc(1, sizeof(sock_info_t));
  GO_TO_ERR_ON_MALLOC_FAIL(sock_info, sock_info_err);

  sock_info->request_handler = request_handler;
  sock_info->loop = request_handler->loop;
  code = setsock(sock_info, sock, easy, action, request_handler);
  GO_TO_ON_ASSERT(code == HTTP2_RH_SUCCESS, "setsock failed", set_sock_err);

  code = curl_multi_assign(request_handler->multi, sock, sock_info);
  GO_TO_ON_ASSERT(code == CURLM_OK, "curl_multi_assign failed", curl_multi_err);

  return HTTP2_RH_SUCCESS;

curl_multi_err:
set_sock_err:
  free(sock_info);
sock_info_err:
  return HTTP2_RH_ERROR;
}

/* CURLMOPT_SOCKETFUNCTION */
static int
sock_cb(CURL* easy, curl_socket_t sock, int what, void* ctx, void* sockp) {
  int code = 0;
  http2_request_handler_t* client = (http2_request_handler_t*)ctx;
  sock_info_t* sock_info = (sock_info_t*)sockp;

  if (what == CURL_POLL_REMOVE) {
    remsock(sock_info);
  } else {
    if (!sock_info) {
      code = addsock(sock, easy, what, client);
    } else {
      code = setsock(sock_info, sock, easy, what, client);
    }
  }
  return code;
}

/* CURLOPT_HEADERFUNCTION */
static size_t header_cb(void* ptr, size_t size, size_t nmemb, void* data) {
  size_t realsize = size * nmemb;
  http2_request_t* request = (http2_request_t*)data;
  (void)ptr;
  char* buf = ptr;
  size_t clen_h_size = strlen(CONTENT_LENGTH_HEADER);
  if (strncmp(buf, CONTENT_LENGTH_HEADER, clen_h_size) == 0) {
    request->response->is_stream = FALSE;
    request->response->content_len = atoi(buf + clen_h_size);
  }
  return realsize;
}

/* CURLOPT_WRITEFUNCTION */
static size_t write_cb(void* ptr, size_t size, size_t nmemb, void* data) {
  size_t realsize = size * nmemb;
  http2_request_t* req = (http2_request_t*)data;
  (void)ptr;
  char* buf = ptr;
  if (req == NULL || req->response == NULL) {
    RAD_PROXY_LOG_ERR("Received NULL parameter");
    return 0;
  }
  // if response is a stream just call the response handler callback
  if (req->response->is_stream) {
    req->response->response_cb(
        req->response->headers,
        buf,
        realsize,
        req->response->is_stream,
        req->context);
    return realsize;
  }

  // Get chunks at call the response handler once we got all data
  req->response->body =
      (char*)realloc(req->response->body, req->response->len + realsize + 1);
  if (req->response->body == NULL) {
    // TODO: add proper logging in this case.
    return 0;
  }
  memcpy(&(req->response->body[req->response->len]), buf, realsize);
  req->response->len += realsize;
  req->response->body[req->response->len] = 0;
  if (req->response->content_len != 0 &&
      req->response->len >= req->response->content_len) {
    RAD_PROXY_LOG_PII_TRACE("Recieved response: %s", req->response->body);
    req->response->response_cb(
        req->response->headers,
        req->response->body,
        req->response->len,
        req->response->is_stream,
        req->context);
  }
  return realsize;
}

http2_request_handler_t* init_http2_request_handler(struct ev_loop* loop) {
  if (loop == NULL) {
    RAD_PROXY_LOG_ERR("Recevied NULL parameter");
    return NULL;
  }
  CURLMcode rc;
  http2_request_handler_t* request_handler =
      (http2_request_handler_t*)malloc(sizeof(http2_request_handler_t));
  GO_TO_ERR_ON_MALLOC_FAIL(request_handler, req_handler_err);

  request_handler->loop = loop;
  request_handler->multi = curl_multi_init();
  GO_TO_ERR_ON_MALLOC_FAIL(request_handler->multi, curl_multi_init_err);

  ev_timer_init(&request_handler->timer_event, timer_cb, 0., 0.);
  request_handler->timer_event.data = request_handler;

  /* setup the generic multi interface options we want */
  rc = curl_multi_setopt(
      request_handler->multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLMOPT_SOCKETFUNCTION err\n", curl_setopt_error);
  rc = curl_multi_setopt(
      request_handler->multi, CURLMOPT_SOCKETDATA, request_handler);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLMOPT_SOCKETDATA err\n", curl_setopt_error);
  rc = curl_multi_setopt(
      request_handler->multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLMOPT_TIMERFUNCTION err\n", curl_setopt_error);
  rc = curl_multi_setopt(
      request_handler->multi, CURLMOPT_TIMERDATA, request_handler);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLMOPT_TIMERDATA err\n", curl_setopt_error);

  // We want single HTTP/2 connection for that host and request multipliexing
  // TODO: make CURLMOPT_MAXCONNECTS configurable to WAC proxy mode.
  rc = curl_multi_setopt(
      request_handler->multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLMOPT_PIPELINING err\n", curl_setopt_error);
  rc = curl_multi_setopt(request_handler->multi, CURLMOPT_MAXCONNECTS, 1L);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLMOPT_MAXCONNECTS err\n", curl_setopt_error);

  return request_handler;

curl_setopt_error:
  curl_multi_cleanup(request_handler->multi);
curl_multi_init_err:
  free(request_handler);
req_handler_err:
  return NULL;
}

http2_response_t* init_http2_response(on_response_cb_t response_cb) {
  http2_response_t* r = (http2_response_t*)malloc(sizeof(http2_response_t));
  GO_TO_ERR_ON_MALLOC_FAIL(r, error);
  r->body = NULL;
  r->len = 0;
  r->headers = NULL;
  r->is_stream = TRUE;
  r->response_cb = response_cb;
  r->content_len = 0;
  return r;
error:
  return NULL;
}

void free_http2_response(http2_response_t* r) {
  if (r == NULL) {
    return;
  }
  if (r->body != NULL) {
    free(r->body);
    r->body = NULL;
  }
  r->len = 0;
  if (r->headers != NULL) {
    curl_slist_free_all(r->headers);
    r->headers = NULL;
  }
  r->response_cb = NULL;
  r->content_len = 0;
  free(r);
}

/* NOTE: no need to manually free the request, multi handler will take care of
 * it */
http2_request_t* init_request(
    http2_request_handler_t* request_handler,
    on_response_cb_t response_cb,
    void* context,
    http2_request_context_free_t free_context) {
  http2_request_t* request;
  CURLMcode rc;

  if (request_handler == NULL) {
    RAD_PROXY_LOG_ERR("Received NULL parameter");
    return NULL;
  }

  request = (http2_request_t*)calloc(1, sizeof(http2_request_t));
  GO_TO_ERR_ON_MALLOC_FAIL(request, http2_req_error);
  request->request_handler = request_handler;
  request->easy = curl_easy_init();
  GO_TO_ERR_ON_MALLOC_FAIL(request->easy, curl_easy_error);
  request->response = init_http2_response(response_cb);
  GO_TO_ERR_ON_MALLOC_FAIL(request->response, response_error);

  request->context = context;
  request->free_request_context = free_context;
  rc = curl_easy_setopt(request->easy, CURLOPT_WRITEFUNCTION, write_cb);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_WRITEFUNCTION err\n", curl_setopt_error);
  rc = curl_easy_setopt(request->easy, CURLOPT_WRITEDATA, request);
  GO_TO_ON_ASSERT(rc == CURLM_OK, "CURLOPT_WRITEDATA err\n", curl_setopt_error);
  rc = curl_easy_setopt(request->easy, CURLOPT_HEADERFUNCTION, header_cb);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_HEADERFUNCTION err\n", curl_setopt_error);
  rc = curl_easy_setopt(request->easy, CURLOPT_HEADERDATA, request);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_HEADERDATA err\n", curl_setopt_error);
  // TODO: add proper configuration for debug mode
  rc = curl_easy_setopt(request->easy, CURLOPT_VERBOSE, CURL_DEBUG_OPT);
  GO_TO_ON_ASSERT(rc == CURLM_OK, "CURLOPT_VERBOSE err\n", curl_setopt_error);
  rc = curl_easy_setopt(request->easy, CURLOPT_ERRORBUFFER, request->error);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_ERRORBUFFER err\n", curl_setopt_error);
  rc = curl_easy_setopt(request->easy, CURLOPT_PRIVATE, request);
  GO_TO_ON_ASSERT(rc == CURLM_OK, "CURLOPT_PRIVATE err\n", curl_setopt_error);
  rc = curl_easy_setopt(
      request->easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_HTTP_VERSION err\n", curl_setopt_error);
  rc = curl_easy_setopt(request->easy, CURLOPT_PIPEWAIT, 1L);
  GO_TO_ON_ASSERT(rc == CURLM_OK, "CURLOPT_PIPEWAIT err\n", curl_setopt_error);
  // TODO: add proper configuration for SSL verification
  rc = curl_easy_setopt(request->easy, CURLOPT_SSL_VERIFYPEER, 0L);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_SSL_VERIFYPEER err\n", curl_setopt_error);
  rc = curl_easy_setopt(request->easy, CURLOPT_SSL_VERIFYHOST, 0L);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_SSL_VERIFYHOST err\n", curl_setopt_error);
  return request;

curl_setopt_error:
  free_http2_response(request->response);
  request->context = NULL; // NOTE: the caller should free context on error.
response_error:
  curl_easy_cleanup(request->easy);
  request->easy = NULL;
curl_easy_error:
  free(request);
http2_req_error:
  return NULL;
}

int set_url(http2_request_t* request, char* url) {
  CURLMcode rc;
  if (request->url != NULL) {
    free(request->url);
    request->url = NULL;
  }
  request->url = strdup(url);
  GO_TO_ERR_ON_MALLOC_FAIL(request->url, strdup_err);

  rc = curl_easy_setopt(request->easy, CURLOPT_URL, request->url);
  GO_TO_ON_ASSERT(rc == CURLM_OK, "CURLOPT_URL err\n", curl_setopt_error);

  return HTTP2_RH_SUCCESS;

curl_setopt_error:
  free(request->url);
strdup_err:
  return HTTP2_RH_ERROR;
}

int set_post_data(http2_request_t* request, char* data) {
  CURLMcode rc;
  if (request == NULL || data == NULL) {
    RAD_PROXY_LOG_ERR("Received NULL parameter");
    return HTTP2_RH_ERROR;
  }
  request->data = strdup(data);
  GO_TO_ERR_ON_MALLOC_FAIL(request->data, strdup_err);

  rc = curl_easy_setopt(request->easy, CURLOPT_POSTFIELDS, request->data);
  GO_TO_ON_ASSERT(
      rc == CURLM_OK, "CURLOPT_POSTFIELDS err\n", curl_setopt_error);

  return HTTP2_RH_SUCCESS;

curl_setopt_error:
  free(request->data);
strdup_err:
  return HTTP2_RH_ERROR;
}

int append_headers(http2_request_t* request, char* header) {
  if (request == NULL || header == NULL) {
    RAD_PROXY_LOG_ERR("Received NULL parameter");
    return HTTP2_RH_ERROR;
  }
  request->headers = curl_slist_append(request->headers, header);
  if (request->headers == NULL) {
    RAD_PROXY_LOG_ERR("Memory allocation failed");
    return HTTP2_RH_ERROR;
  }
  return HTTP2_RH_SUCCESS;
}

int submit_request(http2_request_t* request) {
  CURLMcode rc;
  if (request == NULL) {
    RAD_PROXY_LOG_TRACE("Received null parameter");
    return HTTP2_RH_ERROR;
  }
  RAD_PROXY_LOG_PII_TRACE(
      "Sending request (url=%s, data=%s)",
      request->url == NULL ? "null" : request->url,
      request->data == NULL ? "null" : request->data);
  if (request->headers) {
    rc = curl_easy_setopt(request->easy, CURLOPT_HTTPHEADER, request->headers);
    if (rc != CURLM_OK) {
      RAD_PROXY_LOG_ERR("CURLOPT_HTTPHEADER err");
      return HTTP2_RH_ERROR;
    }
  }
  rc = curl_multi_add_handle(request->request_handler->multi, request->easy);
  if (rc != CURLM_OK) {
    RAD_PROXY_LOG_ERR(
        "curl_multi_add_handle failed when sending request: %d", rc);
    return HTTP2_RH_ERROR;
  }
  return HTTP2_RH_SUCCESS;
}

int perform_request(http2_request_t* request) {
  CURLMcode rc;
  int running_handles = 0;

  if (request == NULL) {
    RAD_PROXY_LOG_TRACE("Received null parameter");
    return HTTP2_RH_ERROR;
  }

  rc = curl_multi_perform(request->request_handler->multi, &running_handles);
  if (rc != CURLM_OK) {
    RAD_PROXY_LOG_ERR(
        "curl_multi_perform failed when sending request: %d", rc);
    return HTTP2_RH_ERROR;
  }

  return HTTP2_RH_SUCCESS;
}

void free_request(http2_request_t* request) {
  if (request == NULL) {
    return;
  }
  curl_multi_remove_handle(request->request_handler->multi, request->easy);

  if (request->response) {
    free_http2_response(request->response);
  }

  curl_slist_free_all(request->headers);
  curl_easy_cleanup(request->easy);
  request->free_request_context(request->context);
  free(request->url);
  free(request->data);
  free(request);
}

void free_http2_request_handler(http2_request_handler_t* request_handler) {
  if (request_handler == NULL) {
    return;
  }
  curl_multi_cleanup(request_handler->multi);
  free(request_handler);
}
