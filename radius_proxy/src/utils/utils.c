#include <unistd.h>
#include "utils.h"

#define HOSTNAME_MAX_LEN 1024
char g_hostname[HOSTNAME_MAX_LEN] = {0};

// call once, non-thread-safe
void hostname_init() {
    gethostname(g_hostname, HOSTNAME_MAX_LEN);
}

// gets the hostname of the current machine
const char * hostname_get() {
    return g_hostname;
}

const char* radius_code_to_str(RADIUS_CODE radius_code) {
    switch(radius_code) {
        case RADIUS_CODE_ACCESS_REQUEST:
            return "access-request";
        case RADIUS_CODE_ACCESS_ACCEPT:
            return "access-accept";
        case RADIUS_CODE_ACCESS_REJECT:
            return "access-reject";
        case RADIUS_CODE_ACCOUNTING_REQUEST:
            return "accounting-request";
        case RADIUS_CODE_ACCOUNTING_RESPONSE:
            return "accounting-response";
        case RADIUS_CODE_ACCOUNTING_STATUS:
            return "accounting-status";
        case RADIUS_CODE_DISCONNECT_REQUEST:
            return "disconnect-request";
        case RADIUS_CODE_DISCONNECT_ACK:
            return "disconnect-ack";
        case RADIUS_CODE_DISCONNECT_NACK:
            return "disconnect-nack";
        case RADIUS_CODE_COA:
            return "coa";
        case RADIUS_CODE_COA_ACK:
            return "coa-ack";
        case RADIUS_CODE_COA_NACK:
            return "coa-nack";
        default:
            return "unknown";
    }
}

#ifdef LOG_TO_SCRIBE

// Profiling methods
prof* prof_start(char* event_name, RADIUS_CODE radius_code) {
    prof* p = (prof*)malloc(sizeof(prof));
    p->start_time = clock();
    p->event_name = event_name;
    p->radius_code = radius_code;
    return p;
}

void prof_end_ok(prof* p) {
    int elapsed_time =
        (int)((((double)(clock() - p->start_time)) * 1000000) / CLOCKS_PER_SEC);
    RAD_PROXY_LOG_METRIC(
        "us",
        "SUCCESS",
        p->event_name,
        elapsed_time,
        0,
        p->radius_code,
    );
    free(p);
}

void prof_end_err(prof* p, int error_code) {
    int elapsed_time =
        (int)((((double)(clock() - p->start_time)) * 1000000) / CLOCKS_PER_SEC);
    RAD_PROXY_LOG_METRIC(
        "us",
        "FAILURE",
        p->event_name,
        elapsed_time,
        error_code,
        p->radius_code,
    );
    free(p);
}

#else

prof* prof_start(char* event_name, RADIUS_CODE radius_code) {
    return NULL;
}

void prof_end_err(prof* p, int error_code) {
}

void prof_end_ok(prof* p) {
}

#endif
