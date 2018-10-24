/*
 * 'coa_sse_handle.c' - radius_http_proxy
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

#include "coa_sse_handler.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "config_parser.h"
#include "radius_proxy.h"
#include "utils/b64.h"
#include "utils/jsmn.h"
#include "utils/utils.h"

#define SSE_PING_STR "ping"
#define SSE_EVENT_STR "event"
#define SSE_COA_EVENT_STR "coa"
#define SSE_DATA_STR "data"

/* Forward declaration */
static void coa_sse_publish_cb(
    struct curl_slist* headers,
    char* data,
    size_t len,
    short is_stream,
    void* context);

static void reestablish_sse_conn(coa_sse_handler_t* coa_handler);

/* This CB is called whenever http2 request handler is freeing the request */
static void coa_sse_request_free_cb(void* arg) {
  coa_sse_handler_t* coa_handler = (coa_sse_handler_t*)arg;

  RAD_PROXY_LOG_ERR("SSE request is cleaned by the http2 request handler.");
  /* Mark the http_request pointer as NULL since its geting free'd */
  coa_handler->http_request = NULL;
}

/* This CB is called whenever coa ack request is done*/
static void coa_ack_request_free_ctx_cb(void* arg) {}

/* Dummy HTTP response callback because don't need the response in case of ACK
 */
static void coa_ack_response_dummy_cb(
    struct curl_slist* headers,
    char* data,
    size_t len,
    short is_stream,
    void* context) {}

/* If this timer event fired it means that we didn't receive publish for long
 * time */
static void timer_cb(EV_P_ struct ev_timer* w, int revents) {
  struct coa_event_timer* t = (struct coa_event_timer*)w;
  coa_sse_handler_t* coa_handler = (coa_sse_handler_t*)t->data;

  RAD_PROXY_LOG_ERR("SSE Timeout, reestablishing SSE connection");
  reestablish_sse_conn(coa_handler);
}

/* This function is called when CoA ACK/NAK received from the AP */
static void udp_coa_ack_cb(EV_P_ ev_io* w, int revents) {
  char custom_http_header[MAX_CONFIG_LONG_STR_SIZE + MAX_HTTP_HEADER_NAME_SIZE];
  coa_sse_handler_t* coa_handler = (coa_sse_handler_t*)w->data;
  int fd = coa_handler->coa_fd;
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  char* encoded_packet = NULL;
  char buf[BUFLEN];
  int len;
  int rc;

  if ((len = recvfrom(
           fd,
           buf,
           sizeof(buf) - 1,
           0,
           (struct sockaddr*)&client_addr,
           &client_len)) == -1) {
    RAD_PROXY_LOG_ERR(
      "Failed to receive UDP packet from socket (errno: %d)",
      errno);
    return;
  }

  encoded_packet = encode_radius_packet(buf, len);
  GO_TO_ERR_ON_MALLOC_FAIL(encoded_packet, encode_radius_err);
  http2_request_t* request = init_request(
      coa_handler->http_handler,
      coa_ack_response_dummy_cb,
      NULL,
      coa_ack_request_free_ctx_cb);
  GO_TO_ERR_ON_MALLOC_FAIL(request, http2_request_err);
  rc = set_url(request, conf_opts.coa_ack_graph_api);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set URL failed", rc_err);
  sprintf(
      custom_http_header,
      "%s: %s",
      RAD_PACK_ENC_HEADER,
      conf_opts.radius_packet_encoding);
  rc = append_headers(request, custom_http_header);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set Headers failed\n", rc_err);
  sprintf(
      custom_http_header,
      "%s: %s",
      SSE_CLIENT_MAC_HEADER,
      conf_opts.sse_client_mac_address);
  rc = append_headers(request, custom_http_header);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set Headers failed\n", rc_err);
  rc = set_post_data(request, encoded_packet);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set POST data failed", rc_err);
  rc = submit_request(request);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Submit request failed", rc_err);
  free(encoded_packet);
  return;

rc_err:
  free_request(request);
http2_request_err:
  free(encoded_packet);
encode_radius_err:
  return;
}

/* This function is called when CoA request/disconnect received from SSE server
 */
static int
coa_request_send(coa_sse_handler_t* coa_handler, char* buf, size_t len) {
  char* radius_packet = NULL;
  size_t packet_len;
  int ret = -1;

  radius_packet = decode_radius_packet(buf, len, &packet_len);
  GO_TO_ERR_ON_MALLOC_FAIL(radius_packet, out);

  switch (conf_opts.coa_ip_address_source) {
    case COA_SEND_TO_REQ_LISTEN_IP:
      break;
    case COA_SEND_TO_NAS_IP_ADDRESS:
      coa_handler->sin.sin_addr.s_addr =
        get_nas_ip_address(radius_packet, len);
      GO_TO_ON_ASSERT(
        coa_handler->sin.sin_addr.s_addr != 0,
        "Invalid NAS-IP-Address found in CoA packet",
        out_free_packet
      )
      break;
    default:
      GO_TO_ON_ASSERT(
        FALSE,
        "Invalid config value for 'coa_handling'",
        out_free_packet
      );
  }

  RAD_PROXY_LOG_TRACE(
    "Sending CoA packet to %s:%d",
    inet_ntoa(coa_handler->sin.sin_addr),
    ntohs(coa_handler->sin.sin_port)
  );

  ret = sendto(
      coa_handler->coa_fd,
      radius_packet,
      packet_len,
      0,
      (struct sockaddr*)&coa_handler->sin,
      sizeof(coa_handler->sin));

out_free_packet:
  free(radius_packet);

out:
  return ret;
}

/* This function is called when we have SSE event
 * Note: We assume that the SSE server is always sending the CoA request in
 * one SSE event.
 */
static void coa_sse_publish_cb(
    struct curl_slist* headers,
    char* data,
    size_t len,
    short is_stream,
    void* context) {
  coa_sse_handler_t* coa_handler = (coa_sse_handler_t*)context;
  jsmntok_t t[JSMN_MAX_TOKENS];
  jsmn_parser p;
  int n_tokens;
  int i;

  ev_timer_stop(coa_handler->loop, &coa_handler->timer_event.expire);
  jsmn_init(&p);
  n_tokens = jsmn_parse(&p, data, len, t, JSMN_MAX_TOKENS);
  if (n_tokens < 0) {
    RAD_PROXY_LOG_ERR("Failed to parse JSON: %d", n_tokens);
    return;
  }
  for (i = 0; i < n_tokens; i++) {
    if (!jsmn_eq_untyped(data, &t[i], SSE_PING_STR)) { // PING
      RAD_PROXY_LOG_PII_TRACE("Received SSE ping event");
      break;
    }
    if (!jsmn_eq_untyped(data, &t[i], SSE_EVENT_STR) &&
        jsmn_eq_untyped(data, &t[i + 1], SSE_COA_EVENT_STR)) { // EVENT TYPE
      RAD_PROXY_LOG_ERR("Unexpected SSE event type");
      break;
    }
    if (!i || i == n_tokens - 1)
      continue;

    if (jsmn_eq(data, &t[i], SSE_DATA_STR) == 0) { // COA DECODED DATA
      int n = coa_request_send(
          coa_handler, data + t[i + 1].start, t[i + 1].end - t[i + 1].start);
      if (n < 0)
        RAD_PROXY_LOG_ERR("Failed to send CoA request");
      i++;
    }
  }

  ev_timer_set(&coa_handler->timer_event.expire, coa_handler->sse_timeout, 0.);
  ev_timer_start(coa_handler->loop, &coa_handler->timer_event.expire);
}

/* SSE session establishment */
static http2_request_t* establish_sse_conn(coa_sse_handler_t* coa_handler) {
  int rc = 0;
  char custom_http_header[MAX_CONFIG_LONG_STR_SIZE + MAX_HTTP_HEADER_NAME_SIZE];
  http2_request_t* request = init_request(
      coa_handler->http_handler,
      coa_sse_publish_cb,
      (void*)coa_handler,
      coa_sse_request_free_cb);

  GO_TO_ERR_ON_MALLOC_FAIL(request, http2_request_err);
  rc = set_url(request, conf_opts.coa_sse_api);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set URL failed\n", rc_err);
  rc = append_headers(request, "Accept: text/event-stream");
  sprintf(
      custom_http_header,
      "%s: %s",
      RAD_PACK_ENC_HEADER,
      conf_opts.radius_packet_encoding);
  rc = append_headers(request, custom_http_header);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set Headers failed\n", rc_err);
  if (strlen(conf_opts.generic_sse_http_header)) {
    rc = append_headers(request, conf_opts.generic_sse_http_header);
    GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set Headers failed\n", rc_err);
  }
  sprintf(
      custom_http_header,
      "%s: %s",
      SSE_CLIENT_MAC_HEADER,
      conf_opts.sse_client_mac_address);
  rc = append_headers(request, custom_http_header);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Set Headers failed\n", rc_err);
  rc = submit_request(request);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Submit request failed\n", rc_err);
  rc = perform_request(request);
  GO_TO_ON_ASSERT(rc == HTTP2_RH_SUCCESS, "Perform request failed\n", rc_err);

  ev_timer_set(&coa_handler->timer_event.expire, coa_handler->sse_timeout, 0.);
  ev_timer_start(coa_handler->loop, &coa_handler->timer_event.expire);

  return request;

rc_err:
  free_request(request);
http2_request_err:
  return NULL;
}

/* Close SSE session */
static void stop_sse_connection(coa_sse_handler_t* coa_handler) {
  free_request(coa_handler->http_request);
}

/* SSE session re-establishment */
static void reestablish_sse_conn(coa_sse_handler_t* coa_handler) {
  stop_sse_connection(coa_handler);
  coa_handler->http_request = establish_sse_conn(coa_handler);
}

/* API function to start SSE subscription */
int subscribe_to_coa_requests(coa_sse_handler_t* coa_handler) {
  coa_handler->http_request = establish_sse_conn(coa_handler);
  return coa_handler->http_request ? 0 : -1;
}

/* API function to initialize coa handler data */
coa_sse_handler_t* init_coa_handler(
    struct ev_loop* loop,
    http2_request_handler_t* http_handler) {
  coa_sse_handler_t* coa_handler = NULL;

  if (!loop || !http_handler) {
    RAD_PROXY_LOG_ERR("Received invalid argument");
    return NULL;
  }

  coa_handler = (coa_sse_handler_t*)malloc(sizeof(coa_sse_handler_t));
  GO_TO_ERR_ON_MALLOC_FAIL(coa_handler, handler_alloc_err);
  memset(coa_handler, 0, sizeof(coa_sse_handler_t));
  coa_handler->http_handler = http_handler;
  coa_handler->loop = loop;
  coa_handler->sse_timeout = (ev_tstamp)conf_opts.sse_timeout_secs;

  ev_timer_init(&coa_handler->timer_event.expire, timer_cb, 0., 0.);
  coa_handler->timer_event.data = coa_handler;

  coa_handler->coa_fd =
      socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  GO_TO_ON_ASSERT(
      coa_handler->coa_fd >= 0, "CoA socket creation failed", socket_err);

  memset(&coa_handler->sin, 0, sizeof(coa_handler->sin));
  coa_handler->sin.sin_addr.s_addr = conf_opts.req_listen_ip.s_addr;
  coa_handler->sin.sin_port = htons(conf_opts.coa_port);
  coa_handler->sin.sin_family = AF_INET;

  ev_io_init(
      &coa_handler->coa_ack_event,
      udp_coa_ack_cb,
      coa_handler->coa_fd,
      EV_READ);
  coa_handler->coa_ack_event.data = coa_handler;
  ev_io_start(loop, &coa_handler->coa_ack_event);

  return coa_handler;

socket_err:
  free(coa_handler);
handler_alloc_err:
  return NULL;
}

/* API function to free coa handler data */
void free_coa_handler(coa_sse_handler_t* coa_handler) {
  if (coa_handler == NULL)
    return;

  close(coa_handler->coa_fd);
  stop_sse_connection(coa_handler);
  free(coa_handler);
}
