/*
 * 'config_parser.h' - radius_http_proxy
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

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "utils/b64.h"
#include "utils/utils.h"

#define DEF_LISTEN_IP "127.0.0.1"
#define DEF_ENC "base64/binary"
#define DEF_SSE_TO "40"
#define DEF_AUTH_PORT "1812"
#define DEF_ACCT_PORT "1813"
#define DEF_COA_PORT "3799"
#define DEF_EMPTY_STR ""

#define SSE_CLIENT_MAC_HEADER "sse-client-mac-address"
#define RAD_PACK_ENC_HEADER "radius-packet-encoding"
#define MAX_HTTP_HEADER_NAME_SIZE 100

#define CONFIG_FILE_LINE_SIZE 2048
#define MAX_CONFIG_STR_SIZE 256
#define MAX_CONFIG_LONG_STR_SIZE MAX_CONFIG_STR_SIZE * 4

typedef struct config_list_node config_list_node_t;

struct config_list_node {
  char* key;
  char* value;
  config_list_node_t* next;
};

struct config_options {
  char partner_short_name[MAX_CONFIG_STR_SIZE];
  char radius_packet_encoding[MAX_CONFIG_STR_SIZE];
  char sse_client_mac_address[MAX_CONFIG_STR_SIZE];
  char auth_graph_api[MAX_CONFIG_STR_SIZE];
  char acct_graph_api[MAX_CONFIG_STR_SIZE];
  char coa_ack_graph_api[MAX_CONFIG_STR_SIZE];
  char coa_sse_api[MAX_CONFIG_STR_SIZE];
  char generic_sse_http_header[MAX_CONFIG_LONG_STR_SIZE];
  struct in_addr req_listen_ip;
  int sse_timeout_secs;
  int auth_port;
  int acct_port;
  int coa_port;
  int coa_handling;
} __attribute__((packed));

typedef struct config_options config_options_t;

typedef enum _config_opt_type {
  CONFIG_FIELD_STRING = 0,
  CONFIG_FIELD_INTEGER,
  CONFIG_FIELD_IPV4,
  CONFIG_FIELD_LONG_STRING,
  CONFIG_FIELD_TYPES_NUM,
} config_opt_type;

typedef enum _coa_handling_type {
  COA_SEND_TO_REQ_LISTEN_IP = 1,
  COA_SEND_TO_NAS_IP_ADDRESS = 2,
} coa_handling_type;

struct config_opt {
  char* name;
  config_opt_type type; /* 0=string, 1=integer, 2=ip */
  int length;
  void* field;
  char* desc;
  char* default_val; /* Default value, if NULL then its mandatory field */
};

/* Including this header will give access to the global config struct */
extern config_options_t conf_opts;

char* get_config_opts_desc(const char* prefix);
int process_config_file(char* filename);

#endif /* CONFIG_PARSER_H */
