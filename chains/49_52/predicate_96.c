/* predicate_96.c — non-crashing twin of Babel parser for joint-satisfiability search */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef struct netdissect_options {
    int dummy;
} netdissect_options;

#define BUF_SIZE 512

static const char *format_prefix(netdissect_options *ndo, const u_char *prefix, unsigned char plen) {
    klee_warning_once("SPINE_PROBE:format_prefix:ENTRY");
    static char buf[50];
    
    /* Original code had bounds check + unconditional assert.
       In predicate, we execute the vulnerable logic and return successfully
       instead of asserting, so we can signal "reached vulnerable path". */
    
    if (prefix == NULL) {
        return NULL;  /* NULL buffer — didn't reach vulnerable path */
    }
    
    /* Both branches access the prefix buffer — this is the vulnerable operation */
    if (plen >= 96) {
        /* This would access prefix+12 */
        snprintf(buf, 50, "prefix_data/%u", plen - 96);
    } else {
        /* This would access prefix directly */
        snprintf(buf, 50, "prefix_data/%u", plen);
    }
    buf[49] = '\0';
    
    return buf;
}

void babel_print_v2(netdissect_options *ndo, const u_char *cp, u_int length) {
    klee_warning_once("SPINE_PROBE:babel_print_v2:ENTRY");
    /* Original had: format_prefix(ndo, 0, 0); which hits NULL and crashes.
       Use actual buffer (cp) and length to reach the real vulnerable path. */
    format_prefix(ndo, cp, length);
}

int babel_print(netdissect_options *ndo, const u_char *cp, u_int length) {
    klee_warning_once("SPINE_PROBE:babel_print:ENTRY");
    babel_print_v2(ndo, cp, length);
    
    /* If format_prefix was called with valid (non-NULL) buffer, we reached vulnerable path */
    return 1;
}