/*
 * 'radius_proxy.h - radius_http_proxy'
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

#ifndef RADIUS_PROXY_H
#define RADIUS_PROXY_H

#include "coa_sse_handler.h"
#include "http2_request_handler.h"
#include "udp_request_handler.h"
#include "utils/utils.h"

#define BUFLEN 4096
#define SIZE 200
#define DATA_FIELD "data="
#define JSMN_MAX_TOKENS 10
#define RADIUS_AVPS_OFFSET_BYTES 20
#define RADIUS_ATTR__NAS_IP_ADDRESS 4
#define RADIUS_ATTR__NAS_IP_ADDRESS_LEN 6


typedef union {
  uint8_t t_octets[254];
  uint32_t t_address;
  uint32_t t_integer;
  uint32_t t_time;
} value_t;

typedef struct {
  uint8_t type;
  uint8_t length;
  value_t val;
} avpt_t;

typedef struct {
  uint8_t code;
  uint8_t identifier;
  uint16_t len;
  uint8_t authenticator[16];
  uint8_t avps[4000];
} radius_packet_t;

typedef struct {
  udp_request_handler_t* auth_handler;
  udp_request_handler_t* acct_handler;
  http2_request_handler_t* http2_request_handler;
  coa_sse_handler_t* coa_handler;
} radius_proxy_t;

typedef struct {
  int fd;
  struct sockaddr_in client_addr;
  prof* profiling;
} radius_proxy_context_t;

typedef enum {
  UPSTREAM = 0,  // Packet from AP to WWW
  DOWNSTREAM     // Packet from WWW to AP
} packet_direction_t;

char* decode_radius_packet(char* buf, size_t len, size_t* packet_len);
char* encode_radius_packet(char* buf, size_t len);
radius_proxy_t* init_radius_proxy(struct ev_loop* loop);
void free_radius_proxy(radius_proxy_t* proxy);
in_addr_t get_nas_ip_address(const char* buf, size_t len);

#endif
