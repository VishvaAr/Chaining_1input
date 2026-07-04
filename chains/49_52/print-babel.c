#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef struct netdissect_options {
    int dummy;
} netdissect_options;

static const char *format_prefix(netdissect_options *ndo, const u_char *prefix, unsigned char plen) {
    klee_warning_once("SPINE_PROBE:format_prefix:ENTRY");
    static char buf[50];
    /* SAILOR: CWE-125 bounds check — injected before vulnerable call */
    if (prefix != NULL && klee_get_obj_size((void*)prefix) >= 12) {
        if (plen >= 96) {
            snprintf(buf, 50, "%u", plen - 96);
        } else {
            snprintf(buf, 50, "%u", plen);
        }
    }
    buf[49] = '\0';
    klee_assert(0 && "SAILOR_SINK_REACHED_BUG96");
    return buf;
}

void babel_print_v2(netdissect_options *ndo, const u_char *cp, u_int length) {
    format_prefix(ndo, cp, length);
    klee_warning_once("SPINE_PROBE:babel_print_v2:ENTRY");
    (void)ndo; (void)cp; (void)length;
}

void babel_print(netdissect_options *ndo, const u_char *cp, u_int length) {
    klee_warning_once("SPINE_PROBE:babel_print:ENTRY");
    babel_print_v2(ndo, cp, length);
}