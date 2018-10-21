/*
 * 'radius_proxy.c' - radius_http_proxy
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

#include "radius_proxy.h"
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config_parser.h"
#include "utils/b64.h"
#include "utils/jsmn.h"
#include "utils/utils.h"

char* concat(const char* s1, const char* s2) {
  char* result = malloc(strlen(s1) + strlen(s2) + 1);
  GO_TO_ERR_ON_MALLOC_FAIL(result, malloc_err);

  strcpy(result, s1);
  strcat(result, s2);
  return result;
malloc_err:
  return NULL;
}

static void free_radius_request_context(void* context) {
  radius_proxy_context_t* c = (radius_proxy_context_t*)context;
  free(c);
}

void log_radius_packet(
  radius_packet_t * packet,
  char * prefix,
  packet_direction_t dir) {
#ifdef VERBOSE_RADIUS_LOG
    uint8_t * a = packet->authenticator;
    printf("--- %s ---\n", prefix);
    printf("Packet Code....................%u\n", packet->code);
    printf("Packet Identifier..............%u\n", packet->identifier);
    printf("Packet Length..................%u\n", htons(packet->len));
    printf("Packet Authenticator...........");
    for (int i = 0; i < 16; i++) {
      if (i % 8 == 0) {
        printf("\n     ");
      }
      printf(" 0x%02X", a[i]);
    }
    printf("\n");

    printf("AVP............................\n");
    int p = 0;
    while (p < packet->len - 20) {
      uint8_t * avp = packet->avps + p;
      int d = avp[0];
      int l = avp[1];
      if (l == 0) {
        break;
      }
      printf("%d\t%d\t", d, l);
      for (int i = 0; i < l; i++) {
        if (i != 0 && i % 8 == 0) {
          printf("\n  \t  \t");
        }
        printf("    0x%02X", avp[p + 2 + i]);
      }
      printf("\n");
      p += l;
    }
#else
  RAD_PROXY_LOG_RADIUS_MSG(
    packet->code,
    packet->identifier,
    htons(packet->len),
    dir == UPSTREAM ? "AP" : "WWW",
    dir == UPSTREAM ? "WWW" : "AP");
#endif
}

char* decode_radius_packet(char* buf, size_t len, size_t* packet_len) {
  size_t dec_buf_len;
  radius_packet_t packet;

  if (buf == NULL || packet_len == NULL) {
    RAD_PROXY_LOG_ERR("Received null parameter");
    return NULL;
  }
  char* dec_buf = b64_decode_ex(buf, len, &dec_buf_len);
  GO_TO_ERR_ON_MALLOC_FAIL(dec_buf, b64_dec_err);

  memcpy(&packet, dec_buf, dec_buf_len);
  log_radius_packet(&packet, "Decoding RADIUS packet", DOWNSTREAM);
  *packet_len = htons(packet.len);
  return dec_buf;

b64_dec_err:
  return NULL;
}

in_addr_t get_nas_ip_address(const char* buf, size_t len) {
  const radius_packet_t * p = (radius_packet_t *)buf;
  uint8_t* avps = (uint8_t*)p->avps;
  char nas_ip_addr[INET_ADDRSTRLEN + 1] = {0};
  int pos = 0;
  while (pos < len - 1) {
    int attr_len = avps[pos+1];
    if (avps[pos] == RADIUS_ATTR__NAS_IP_ADDRESS) {
      GO_TO_ON_ASSERT(
        attr_len == RADIUS_ATTR__NAS_IP_ADDRESS_LEN,
        "Unexpected NAS-IP-Address attribute length (expected 6)",
        out);
      sprintf(
        nas_ip_addr,
        "%d.%d.%d.%d",
        avps[pos+2], avps[pos+3], avps[pos+4], avps[pos+5]
      );
      RAD_PROXY_LOG_TRACE("Got CoA with NAS-IP-Address = %s", nas_ip_addr);

      // Encode the target ip address
      in_addr_t encoded_addr;
      int ip_convert_result = inet_pton(AF_INET, nas_ip_addr, &encoded_addr);
      GO_TO_ON_ASSERT(
        ip_convert_result == 1,
        "Failed to convert address to 32-bit representation",
        out);
      return encoded_addr;
    }

    if (attr_len == 0) {
      break;
    }
    pos += attr_len;
  }
  RAD_PROXY_LOG_TRACE("Could not find NAS-IP-Address field in CoA message");
out:
  return 0;
}

char* encode_radius_packet(char* buf, size_t len) {
  radius_packet_t packet;
  if (buf == NULL) {
    RAD_PROXY_LOG_ERR("Received NULL parameter");
    return NULL;
  }
  memcpy(&packet, buf, len);
  log_radius_packet(&packet, "Encoding RADIUS packet", UPSTREAM);
  char* enc_buf = b64_encode(buf, len);
  GO_TO_ERR_ON_MALLOC_FAIL(enc_buf, b64_enc_err);
  char* res = concat(DATA_FIELD, enc_buf);
  GO_TO_ERR_ON_MALLOC_FAIL(res, concat_err);
  free(enc_buf);
  return res;

concat_err:
  free(enc_buf);
  enc_buf = NULL;
b64_enc_err:
  return NULL;
}

static void radius_response_cb(
    struct curl_slist* headers,
    char* data,
    size_t len,
    short is_stream,
    void* context) {
  char* radius_packet = NULL;
  radius_proxy_context_t* radius_proxy_context =
      (radius_proxy_context_t*)context;
  prof_end_ok(radius_proxy_context->profiling);

  int i;
  int n_tokens;
  jsmn_parser p;
  jsmntok_t t[JSMN_MAX_TOKENS];
  jsmn_init(&p);
  n_tokens = jsmn_parse(&p, data, len, t, JSMN_MAX_TOKENS);
  if (n_tokens < 0) {
    printf("Failed to parse JSON: %d\n", n_tokens);
    return;
  }

  for (i = 1; i < n_tokens - 1; i++) {
    if (jsmn_eq(data, &t[i], "data") == 0) {
      size_t packet_len;
      radius_packet = decode_radius_packet(
        data + t[i + 1].start, t[i + 1].end - t[i + 1].start,
        &packet_len
      );
      int n = sendto(
          radius_proxy_context->fd,
          radius_packet,
          packet_len,
          0,
          (struct sockaddr*)&radius_proxy_context->client_addr,
          sizeof(radius_proxy_context->client_addr));
      free(radius_packet);
      if (n < 0)
        RAD_PROXY_LOG_ERR("Failed to send RADIUS response");
      i++;
    }
  }
}

static void
udp_radius_cb(struct ev_loop* loop, struct ev_io* io, int revents, char* url) {
  char custom_http_header[MAX_CONFIG_LONG_STR_SIZE + MAX_HTTP_HEADER_NAME_SIZE];
  struct sockaddr_in client_addr;
  radius_proxy_t* proxy = (radius_proxy_t*)io->data;
  socklen_t client_len = sizeof(client_addr);
  char* encoded_packet = NULL;
  char buf[BUFLEN];
  int len;
  int rc = 0;

  if ((len = recvfrom(
           io->fd,
           buf,
           sizeof(buf) - 1,
           0,
           (struct sockaddr*)&client_addr,
           &client_len)) == -1) {
    RAD_PROXY_LOG_ERR("Failed receving UDP packet from socket");
    return;
  }
  radius_proxy_context_t* context =
      (radius_proxy_context_t*)malloc(sizeof(radius_proxy_context_t));
  uint8_t radius_code = (buf == NULL) ? 0 : ((radius_packet_t*)buf)->code;
  context->profiling = prof_start("HTTP_REQUEST", radius_code);
  GO_TO_ERR_ON_MALLOC_FAIL(context, radius_proxy_context_err);
  encoded_packet = encode_radius_packet(buf, len);
  GO_TO_ERR_ON_MALLOC_FAIL(encoded_packet, encode_radius_err);
  context->fd = io->fd;
  context->client_addr = client_addr;
  http2_request_t* request = init_request(
      proxy->http2_request_handler,
      radius_response_cb,
      (void*)context,
      free_radius_request_context);
  GO_TO_ERR_ON_MALLOC_FAIL(request, http2_request_err);
  rc = set_url(request, url);
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
  free_radius_request_context(context);
radius_proxy_context_err:
  prof_end_err(context->profiling, rc);
  return;
}

static void udp_auth_cb(struct ev_loop* loop, struct ev_io* io, int revents) {
  udp_radius_cb(loop, io, revents, conf_opts.auth_graph_api);
}

static void udp_acct_cb(struct ev_loop* loop, struct ev_io* io, int revents) {
  udp_radius_cb(loop, io, revents, conf_opts.acct_graph_api);
}

radius_proxy_t* init_radius_proxy(struct ev_loop* loop) {
  http2_request_handler_t* http2_request_handler = NULL;
  udp_request_handler_t* auth_handler = NULL;
  udp_request_handler_t* acct_handler = NULL;
  radius_proxy_t* proxy = NULL;
  coa_sse_handler_t* coa_handler = NULL;
  int rc = 0;

  if (loop == NULL) {
    RAD_PROXY_LOG_ERR("Received NULL parameter");
    return NULL;
  }

  proxy = (radius_proxy_t*)malloc(sizeof(radius_proxy_t));
  GO_TO_ERR_ON_MALLOC_FAIL(proxy, radius_proxy_err);
  http2_request_handler = init_http2_request_handler(loop);
  GO_TO_ERR_ON_MALLOC_FAIL(http2_request_handler, http2_req_handler_err);
  auth_handler = init_udp_request_handler(
      loop, conf_opts.auth_port, udp_auth_cb, (void*)proxy);
  GO_TO_ERR_ON_MALLOC_FAIL(auth_handler, auth_handler_err);
  acct_handler = init_udp_request_handler(
      loop, conf_opts.acct_port, udp_acct_cb, (void*)proxy);
  GO_TO_ERR_ON_MALLOC_FAIL(acct_handler, acct_handler_err);
  coa_handler = init_coa_handler(loop, http2_request_handler);
  GO_TO_ERR_ON_MALLOC_FAIL(coa_handler, coa_handler_err);
  rc = subscribe_to_coa_requests(coa_handler);
  GO_TO_ON_ASSERT(rc == 0, "CoA SSE subscription failed", coa_sub_err);
  proxy->coa_handler = coa_handler;
  proxy->http2_request_handler = http2_request_handler;
  proxy->auth_handler = auth_handler;
  proxy->acct_handler = acct_handler;

  return proxy;

coa_sub_err:
  free_coa_handler(coa_handler);
coa_handler_err:
  free_udp_request_handler(acct_handler);
acct_handler_err:
  free_udp_request_handler(auth_handler);
  auth_handler = NULL;
auth_handler_err:
  free_http2_request_handler(http2_request_handler);
  http2_request_handler = NULL;
http2_req_handler_err:
  free(proxy);
  proxy = NULL;
radius_proxy_err:
  return NULL;
}

void free_radius_proxy(radius_proxy_t* proxy) {
  if (proxy == NULL) {
    return;
  }
  free_coa_handler(proxy->coa_handler);
  free_udp_request_handler(proxy->auth_handler);
  free_udp_request_handler(proxy->acct_handler);
  free_http2_request_handler(proxy->http2_request_handler);
  free(proxy);
}
