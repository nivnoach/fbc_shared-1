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

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

void hostname_init();
const char * hostname_get();

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
// profiling interface
// to emit profiling logs, use the following pattern:
//
//     prof op_prof = prof_start("Event Name", RADIUS_CODE_NONE);
//
//     int err_code = do_operation();
//
//     if (fail) {
//       prof_end_err(op_prof, err_code);
//     } else {
//       prof_end_ok(op_prof);
//     }
//
typedef struct _prof {
    int start_time;
    char * event_name;
    RADIUS_CODE radius_code;
} prof;

prof * prof_start(char* event_name, RADIUS_CODE radius_code);
void prof_end_ok(prof* p);
void prof_end_err(prof* p, int error_code);

//////////////////////////////////////////////////////////////////////
// Utility method for converting radius code to a string, for example:
//   radius_code_to_str(RADIUS_CODE_COA) ==> "coa"
// 
const char* radius_code_to_str(RADIUS_CODE radius_code);

/////////////////////////////////////////////////////////////////////
// define logging macros
#ifdef LOG_TO_SCRIBE
#include "logging_scribe.h"
#else
#include "logging_stdout.h"
#endif

/////////////////////////////////////////////////////////////////////
// error handling macros
#define GO_TO_ON_ASSERT(cond, msg, label) do {if (!(cond)) { RAD_PROXY_LOG_ERR(msg); goto label; }} while (0);
#define GO_TO_ERR_ON_MALLOC_FAIL(val, label) GO_TO_ON_ASSERT(val != NULL, "malloc failed", label);
#define SAFE_RETURN_ON_NULL(val) do {if (val == NULL) { RAD_PROXY_LOG_ERR("Got unexpected null value"); goto error; }} while(0);

#endif
