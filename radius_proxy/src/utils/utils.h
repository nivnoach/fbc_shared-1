/*
 * 'utils.h' - radius_http_proxy
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
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include "config_parser.h"

extern int debug_verbosity;

#define TRUE 1
#define FALSE 0

#ifdef CURL_DEBUG
#define CURL_DEBUG_OPT 1
#else
#define CURL_DEBUG_OPT 0
#endif

void hostname_init();
const char * hostname_get();

// utility method to replace a char with another in a string.
// replaces all occurences
static inline void replace_char(char * s, char replace, char replace_with) {
    for(int i = 0; s[i] != 0; i++) {
        if (s[i] == replace) {
            s[i] = replace_with;
        }
    }
}

// RADIUS Codes
typedef int RADIUS_CODE;

#define RADIUS_CODE_NONE 0
#define RADIUS_CODE_ACCESS_REQUEST 1
#define RADIUS_CODE_ACCESS_ACCEPT 2
#define RADIUS_CODE_ACCESS_REJECT 3
#define RADIUS_CODE_ACCOUNTING_REQUEST 4
#define RADIUS_CODE_ACCOUNTING_RESPONSE 5
#define RADIUS_CODE_ACCOUNTING_STATUS 6
#define RADIUS_CODE_DISCONNECT_REQUEST 40
#define RADIUS_CODE_DISCONNECT_ACK 41
#define RADIUS_CODE_DISCONNECT_NACK 42
#define RADIUS_CODE_COA 43
#define RADIUS_CODE_COA_ACK 44
#define RADIUS_CODE_COA_NACK 45

//////////////////////////////////////////////////////////////////////
// profiling type. to emit profiling logs, use the following pattern:
//
// prof op_prof = prof_start("Event Name", RADIUS_CODE_NONE);
// /* do operation */
// if (fail) {
//  prof_end_err(op_prof, 7018);
// } else {
//  prof_end_ok(op_prof);
// }
//

typedef struct _prof {
    int start_time;
    char * event_name;
    RADIUS_CODE radius_code;
} prof;

prof * prof_start(char* event_name, RADIUS_CODE radius_code);
void prof_end_ok(prof* p);
void prof_end_err(prof* p, int error_code);

const char* radius_code_to_str(int radius_code);

/////////////////////////////////////////////////////////////////////
// define macros based on logging format
//
#define DEFAULT_LOG_VALUE -1
#define DEFAULT_LOG_RADIUS_CODE -1
#define DEFAULT_LOG_ERROR_CODE -1
#define DEFAULT_LOG_LENGTH -1

#ifdef LOG_TO_SCRIBE
#include <time.h>
#define LOG_FMT "{ \
                    \"int\": { \
                        \"time\": %lu, \
                        \"file_line\": %d, \
                        \"value\": %d, \
                        \"radius_code\": %d, \
                        \"error_code\": %d, \
                        \"length\": %d \
                    }, \
                    \"normal\": { \
                        \"hostname\": \"%s\", \
                        \"level\": \"%s\", \
                        \"event_name\": \"%s\", \
                        \"radius_type\": \"%s\", \
                        \"file_name\": \"%s\", \
                        \"message\": \"%s\", \
                        \"unit\":\"%s\", \
                        \"source\":\"%s\", \
                        \"target\":\"%s\", \
                        \"partner_short_name\": \"%s\" \
                    } \
                }\n"
#define RAD_PROXY_LOG(level, event, fmt, ...) \
  do { \
    char __a_msg[1024]; \
    sprintf(__a_msg, fmt, ##__VA_ARGS__); \
    replace_char(__a_msg, '"', '\''); \
    fprintf(stdout, LOG_FMT, \
            (unsigned long)time(NULL), __LINE__, DEFAULT_LOG_VALUE, \
            DEFAULT_LOG_RADIUS_CODE, DEFAULT_LOG_ERROR_CODE, DEFAULT_LOG_LENGTH, \
            hostname_get(), level, event, "", __FILE__, \
            (char*)__a_msg, "", "", "", conf_opts.partner_short_name); \
  } while (0);
#define RAD_PROXY_LOG_PII_TRACE(fmt, ...)
#define RAD_PROXY_LOG_PII_ERR(fmt, ...)
#define RAD_PROXY_LOG_TRACE(fmt, ...) \
  RAD_PROXY_LOG("TRACE", "LOG", fmt, ##__VA_ARGS__)
#define RAD_PROXY_LOG_ERR(fmt, ...) \
  RAD_PROXY_LOG("ERROR", "LOG", fmt, ##__VA_ARGS__)
#define RAD_PROXY_LOG_METRIC(unit, level, metric, value, error_code, radius_code, ...) \
    do { \
      fprintf(stdout, LOG_FMT, \
            (unsigned long)time(NULL), __LINE__, value, radius_code, error_code, \
            DEFAULT_LOG_LENGTH, \
            hostname_get(), level, metric, radius_code_to_str(radius_code), \
            __FILE__, "", unit, "", "", conf_opts.partner_short_name); \
    } while (0);
#define RAD_PROXY_LOG_RADIUS_MSG(radius_code, id, len, source, target) \
    do { \
      fprintf(stdout, LOG_FMT, \
            (unsigned long)time(NULL), __LINE__, DEFAULT_LOG_VALUE, radius_code, \
            DEFAULT_LOG_ERROR_CODE, len, \
            hostname_get(), "DEBUG", "RADIUS_MSG", \
            radius_code_to_str(radius_code), __FILE__, "", "", \
            source, target, conf_opts.partner_short_name); \
    } while (0);
#else
#define RAD_PROXY_LOG_PII_TRACE(fmt, ...) RAD_PROXY_LOG_TRACE(fmt, ##__VA_ARGS__)
#define RAD_PROXY_LOG_PII_ERR(fmt, ...) RAD_PROXY_LOG_ERR(fmt, ##__VA_ARGS__)
#define RAD_PROXY_LOG_TRACE(fmt, ...) do { if (debug_verbosity) fprintf(stderr, "[TRACE][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); fprintf(stderr, "\n"); } while (0);
#define RAD_PROXY_LOG_ERR(fmt, ...) do { fprintf(stderr, "[ERROR][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); fprintf(stderr, "\n"); } while (0);
#define RAD_PROXY_LOG_METRIC(unit, level, metric, value, error_code, radius_code, ...)
#define RAD_PROXY_LOG_RADIUS_MSG(code, id, len, source, target) \
        fprintf(stderr, "[RADIUS][%s:%d] (%02d) %s | id %d | %d bytes| %s ==> %s\n", \
        __FILE__, __LINE__, code, radius_code_to_str(code), \
        id, len, source, target)
#endif

/////////////////////////////////////////////////////////////////////
// error handling macros
#define GO_TO_ON_ASSERT(cond, msg, label) do {if (!(cond)) { RAD_PROXY_LOG_ERR(msg); goto label; }} while (0);
#define GO_TO_ERR_ON_MALLOC_FAIL(val, label) GO_TO_ON_ASSERT(val != NULL, "malloc failed", label);
#define SAFE_RETURN_ON_NULL(val) do {if (val == NULL) { RAD_PROXY_LOG_ERR("Got unexpected null value"); goto error; }} while(0);

#endif
