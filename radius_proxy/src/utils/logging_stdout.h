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

#ifndef LOGGIN_STDOUT_H

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
