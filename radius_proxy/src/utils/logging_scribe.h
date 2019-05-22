/*
 * 'logging_scribe.h' - radius_http_proxy
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

#ifndef __LOGGING_SCRIBE_H
#define __LOGGING_SCRIBE_H

#define DEFAULT_LOG_VALUE -1
#define DEFAULT_LOG_RADIUS_CODE -1
#define DEFAULT_LOG_ERROR_CODE -1
#define DEFAULT_LOG_LENGTH -1

// utility method to replace a char with another in a string.
// replaces all occurences
static inline void replace_char(char * s, char replace, char replace_with) {
    for(int i = 0; s[i] != 0; i++) {
        if (s[i] == replace) {
            s[i] = replace_with;
        }
    }
}

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
#define RAD_PROXY_LOG_TRACE(fmt, ...)  RAD_PROXY_LOG("TRACE", "LOG", fmt, ##__VA_ARGS__)
#define RAD_PROXY_LOG_ERR(fmt, ...)    RAD_PROXY_LOG("ERROR", "LOG", fmt, ##__VA_ARGS__)
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

#endif
