#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>     
#include <klee/klee.h>

typedef unsigned char u_char;

typedef struct netdissect_options_b94 {
    int ndo_eflag;
    int ndo_suppress_default_print;
} netdissect_options_b94;

struct pcap_pkthdr_b94 {
    uint32_t len;
    uint32_t caplen;
};

typedef struct netdissect_options_b96 {
    int dummy;
} netdissect_options_b96;

extern int cip_if_print(netdissect_options_b94 *ndo,
                        const struct pcap_pkthdr_b94 *h, const u_char *p);
extern int babel_print(netdissect_options_b96 *ndo, const u_char *cp, u_int length);

int main(void) {
    /* ONE shared symbolic buffer for both */
    unsigned char *buf = calloc(1, 512);
    klee_make_symbolic(buf, 512, "buf");

    /* Shared symbolic length value */
    uint32_t sym_len;
    klee_make_symbolic(&sym_len, sizeof(sym_len), "len");
    
    /* Unified constraints: both bugs must be reachable */
    klee_assume(sym_len >= 6 && sym_len <= 512);
    
    /* Bug 94 structures */
    netdissect_options_b94 ndo94 = {0};
    struct pcap_pkthdr_b94 h94 = {.len = sym_len, .caplen = sym_len};

    /* Bug 96 structures */
    netdissect_options_b96 ndo96 = {0};

    /* Call BOTH with SAME shared input */
    int r94 = cip_if_print(&ndo94, &h94, buf);
    int r96 = babel_print(&ndo96, buf, sym_len);

    /* Force BOTH vulnerable branches to be reached */
    klee_assume(r94 == 1);
    klee_assume(r96 == 1);

    /* Materialize concrete test case */
    klee_assert(0 && "BOTH_BUGS_TRIGGERED_SHARED_INPUT");

    free(buf);
    return 0;
}