/*
 * 'config_parser.c' - radius_http_proxy
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

#include "config_parser.h"

/* Global configuration options structure */
config_options_t conf_opts;

static struct config_opt opts[] = {
    {"partner_short_name",
    CONFIG_FIELD_STRING,
    sizeof(conf_opts.partner_short_name),
    conf_opts.partner_short_name,
    "(Optional) The short name of the partner. Used for logging",
    NULL},
    {"req_listen_ip",
     CONFIG_FIELD_IPV4,
     sizeof(conf_opts.req_listen_ip),
     &conf_opts.req_listen_ip,
     "IP address to receive requests on",
     DEF_LISTEN_IP},
    {"sse_client_mac_address",
     CONFIG_FIELD_STRING,
     sizeof(conf_opts.sse_client_mac_address),
     conf_opts.sse_client_mac_address,
     "SSE subscriber (AP/WAC) MAC address for unique client identification",
     NULL},
    {"radius_packet_encoding",
     CONFIG_FIELD_STRING,
     sizeof(conf_opts.radius_packet_encoding),
     conf_opts.radius_packet_encoding,
     "Radius packet encoding",
     DEF_ENC},
    {"auth_graph_api",
     CONFIG_FIELD_STRING,
     sizeof(conf_opts.auth_graph_api),
     conf_opts.auth_graph_api,
     "Authentication Graph API URL to authenticate new users",
     NULL},
    {"acct_graph_api",
     CONFIG_FIELD_STRING,
     sizeof(conf_opts.acct_graph_api),
     conf_opts.acct_graph_api,
     "Accounting Graph API URL to authenticate new users",
     NULL},
    {"coa_ack_graph_api",
     CONFIG_FIELD_STRING,
     sizeof(conf_opts.coa_ack_graph_api),
     conf_opts.coa_ack_graph_api,
     "CoA ACK/NAK Graph API URL to acknowledge receiving CoA requests",
     NULL},
    {"coa_sse_api",
     CONFIG_FIELD_STRING,
     sizeof(conf_opts.coa_sse_api),
     conf_opts.coa_sse_api,
     "CoA Requests SSE subscription API URL to receive on CoA events",
     NULL},
    {"generic_sse_http_header",
     CONFIG_FIELD_LONG_STRING,
     sizeof(conf_opts.generic_sse_http_header),
     conf_opts.generic_sse_http_header,
     "CoA Requests SSE subscription API URL to receive on CoA events",
     DEF_EMPTY_STR},
    {"sse_timeout_secs",
     CONFIG_FIELD_INTEGER,
     sizeof(conf_opts.sse_timeout_secs),
     &conf_opts.sse_timeout_secs,
     "Max time for idle SSE channel (in seconds)",
     DEF_SSE_TO},
    {"auth_port",
     CONFIG_FIELD_INTEGER,
     sizeof(conf_opts.auth_port),
     &conf_opts.auth_port,
     "RADIUS Authentication port",
     DEF_AUTH_PORT},
    {"acct_port",
     CONFIG_FIELD_INTEGER,
     sizeof(conf_opts.acct_port),
     &conf_opts.acct_port,
     "RADIUS Accounting port",
     DEF_ACCT_PORT},
    {"coa_port",
     CONFIG_FIELD_INTEGER,
     sizeof(conf_opts.coa_port),
     &conf_opts.coa_port,
     "RADIUS CoA request port",
     DEF_COA_PORT},
     {"coa_ip_address_source",
      CONFIG_FIELD_INTEGER,
      sizeof(conf_opts.coa_ip_address_source),
      &conf_opts.coa_ip_address_source,
      "Determine the source of the IP to sent CoA to",
      DEF_COA_IP_ADDR_SOURCE},
  };

static int args_count = sizeof(opts) / sizeof(struct config_opt);
static int process_config_list(config_list_node_t* head) {
  config_list_node_t* tmp_opt = NULL;
  char* arg_val = NULL;
  int i = 0;

  for (i = 0; i < args_count; i++) {
    tmp_opt = head;
    /* loop until key found or list ends */
    while (tmp_opt && strcmp(opts[i].name, tmp_opt->key))
      tmp_opt = tmp_opt->next;

    if (!tmp_opt) { // key not found
      if (!opts[i].default_val) {
        RAD_PROXY_LOG_ERR(
            "Missing mandatory configuration file attribute %s",
            opts[i].name);
        return -1;
      }
      arg_val = opts[i].default_val;
    } else { // key found
      arg_val = tmp_opt->value;
    }

    RAD_PROXY_LOG_TRACE(
        "Parsing config argument : arg name=\"%s\",arg val=\"%s\"",
        opts[i].name,
        arg_val);
    switch (opts[i].type) {
      case CONFIG_FIELD_STRING:
        if (strlen(arg_val) >= MAX_CONFIG_STR_SIZE) {
          RAD_PROXY_LOG_ERR(
              "Invalid string value (should be shorter than %d chars) in opt %s",
              MAX_CONFIG_STR_SIZE,
              opts[i].name);
          return -1;
        }
        strcpy(((char*)opts[i].field), arg_val);
        break;
      case CONFIG_FIELD_LONG_STRING:
        if (strlen(arg_val) >= MAX_CONFIG_LONG_STR_SIZE) {
          RAD_PROXY_LOG_ERR(
              "Invalid string value (should be shorter than %d chars) in opt %s",
              MAX_CONFIG_LONG_STR_SIZE,
              opts[i].name);
          return -1;
        }
        strcpy(((char*)opts[i].field), arg_val);
        break;
      case CONFIG_FIELD_INTEGER: {
        int n = atoi(arg_val);
        if (!n) {
          RAD_PROXY_LOG_ERR(
              "Invalid integer value (should be > 0): %s for opt %s",
              arg_val,
              opts[i].name);
          return -1;
        }
        *((int*)opts[i].field) = n;
        break;
      }
      case CONFIG_FIELD_IPV4: {
        struct in_addr ip;
        if (!inet_aton(arg_val, &ip)) {
          RAD_PROXY_LOG_ERR(
              "Invalid IP Address: %s for opt %s", arg_val, opts[i].name);
          return -1;
        }
        ((struct in_addr*)opts[i].field)->s_addr = ip.s_addr;
        break;
      }
      default:
        RAD_PROXY_LOG_ERR("Unknown option type");
        return -1;
    }
  }

  return 0;
}

static void free_config_list(config_list_node_t** head) {
  config_list_node_t* co = NULL;

  while (*head) {
    co = *head;
    *head = (*head)->next;
    if (co->value)
      free(co->value);
    free(co->key);
    free(co);
  }
}

static config_list_node_t* parse_config_file(const char* filename) {
  FILE* file;
  char linebuf[CONFIG_FILE_LINE_SIZE];
  config_list_node_t* ret = NULL;
  config_list_node_t* last = NULL;
  config_list_node_t* co = NULL;
  int line_num = 0;
  int equal;
  char *fopt, *farg;
  char* str_index;
  size_t len, next_token;
  char delimiter;

  if ((file = fopen(filename, "r")) == 0) {
    RAD_PROXY_LOG_ERR("Error opening configuration file '%s'", filename);
    return NULL;
  }

  while ((fgets(linebuf, CONFIG_FILE_LINE_SIZE, file)) != 0) {
    ++line_num;
    len = strlen(linebuf);
    if (len > (CONFIG_FILE_LINE_SIZE - 1)) {
      RAD_PROXY_LOG_ERR(
          "%s:%d: Line too long in configuration file", filename, line_num);
      goto free_ret_list;
    }

    /* find first non-whitespace character in the line */
    next_token = strspn(linebuf, " \t\r\n");
    str_index = linebuf + next_token;

    if (str_index[0] == '\0' || str_index[0] == '#')
      continue; /* empty line or comment line is skipped */

    fopt = str_index;

    /* truncate fopt at the end of the first non-valid character */
    next_token = strcspn(fopt, " \t\r\n=");

    if (fopt[next_token] == '\0') { /* the line is over */
      farg = 0;
      equal = 0;
      goto noarg;
    }

    /* remember if equal sign is present */
    equal = (fopt[next_token] == '=');
    fopt[next_token++] = '\0';

    /* advance pointers to the next token after the end of fopt */
    next_token += strspn(fopt + next_token, " \t\r\n");

    /* check for the presence of equal sign, and if so, skip it */
    if (!equal) {
      if ((equal = (fopt[next_token] == '='))) {
        next_token++;
        next_token += strspn(fopt + next_token, " \t\r\n");
      }
    }
    str_index += next_token;

    /* find argument */
    farg = str_index;
    if (farg[0] == '\"' || farg[0] == '\'') { /* quoted argument */
      str_index = strchr(++farg, str_index[0]); /* skip opening quote */
      if (!str_index) {
        RAD_PROXY_LOG_ERR(
            "%s:%d: unterminated string in configuration file",
            filename,
            line_num);
        goto free_ret_list;
      }
    } else { /* read up the remaining part up to a delimiter */
      next_token = strcspn(farg, " \t\r\n#\'\"");
      str_index += next_token;
    }

    /* truncate farg at the delimiter and store it for further check */
    delimiter = *str_index, *str_index++ = '\0';

    /* everything but comment is illegal at the end of line */
    if (delimiter != '\0' && delimiter != '#') {
      str_index += strspn(str_index, " \t\r\n");
      if (*str_index != '\0' && *str_index != '#') {
        RAD_PROXY_LOG_ERR(
            "%s:%d: Malformed string in configuration file",
            filename,
            line_num);
        goto free_ret_list;
      }
    }

  noarg:
    co = calloc(1, sizeof(config_list_node_t));
    GO_TO_ERR_ON_MALLOC_FAIL(co, free_ret_list);
    co->key = strdup(fopt);
    GO_TO_ERR_ON_MALLOC_FAIL(co->key, co_key_err);
    if (farg) {
      co->value = strdup(farg);
      GO_TO_ERR_ON_MALLOC_FAIL(co->value, co_val_err);
    }
    if (!ret) {
      ret = co;
      last = ret;
      continue;
    }
    last->next = co;
    last = co;
  } /* while */

  goto out;

co_val_err:
  free(co->key);
co_key_err:
  free(co);
free_ret_list:
  free_config_list(&ret);
out:
  if (file)
    fclose(file);
  return ret;
}

#define EXTRA_WHITESPACES_PER_LINE 10
#define TYPE_STR_LEN 20
char config_type_str[][TYPE_STR_LEN] = {
    "string", // CONFIG_FIELD_STRING
    "integer", // CONFIG_FIELD_INTEGER
    "ipv4_str", // CONFIG_FIELD_IPV4
    "long_string", // CONFIG_FIELD_LONG_STRING
};

/* Returns a string that describe the supported configurations */
char* get_config_opts_desc(const char* prefix) {
  int i = 0;
  int desc_len = 0;
  char* ret, *p;

  if (!prefix) {
    RAD_PROXY_LOG_ERR("Invalid prefix given");
    return NULL;
  }

  /*opt_name, type, desc*/
  for (i = 0; i < args_count; i++) {
    desc_len += strlen(prefix) + strlen(opts[i].name) + TYPE_STR_LEN +
        strlen(opts[i].desc) + EXTRA_WHITESPACES_PER_LINE;
  }

  ret = (char*)malloc(desc_len);
  if (!ret)
    return NULL;
  ret[0] = 0;

  p = ret;
  for (i = 0; i < args_count; i++) {
    p += sprintf(
        p,
        "%s%s (%s) : %s.\n",
        prefix,
        opts[i].name,
        config_type_str[opts[i].type],
        opts[i].desc);
  }

  return ret;
}

/* Configuration file parsing */
int process_config_file(char* filename) {
  config_list_node_t* config_list = NULL;
  int err = 0;

  if (!filename || !filename[0]) {
    RAD_PROXY_LOG_ERR("Invalid configuration file name");
    return -1;
  }

  config_list = parse_config_file(filename);
  if (!config_list) {
    RAD_PROXY_LOG_ERR("Parsing configuration options file failed");
    return -1;
  }

  err = process_config_list(config_list);
  free_config_list(&config_list);
  if (err) {
    RAD_PROXY_LOG_ERR("Processing configuration options list failed");
    return err;
  }

  return 0;
}
