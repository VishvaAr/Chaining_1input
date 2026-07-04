#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

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

/* Predicates for bug 94 and 96 */
extern int cip_if_print(netdissect_options_b94 *ndo,
                        const struct pcap_pkthdr_b94 *h, const u_char *p);
extern int babel_print(netdissect_options_b96 *ndo, const u_char *cp, u_int length);

int main(void) {
    /* ONE shared symbolic buffer for both */
    unsigned char *buf = calloc(1, 512);
    klee_make_symbolic(buf, 512, "buf");

    /* Both bugs also need some structure/header info, but keep it simple and shared */
    uint32_t sym_len, sym_caplen;
    klee_make_symbolic(&sym_len, sizeof(sym_len), "len");
    klee_make_symbolic(&sym_caplen, sizeof(sym_caplen), "caplen");
    
    /* Ensure vulnerable paths are reachable:
       - Bug 94 needs cmplen > 0, so both caplen and len must be >= 6
       - Bug 96 needs non-NULL buffer (always true) and valid access
       - Both need buffers within bounds */
    klee_assume(sym_caplen >= 6);
    klee_assume(sym_len >= 6);
    klee_assume(sym_caplen <= 512);
    klee_assume(sym_len >= sym_caplen);
    klee_assume(sym_len <= 512);

    /* Bug 94 structures */
    netdissect_options_b94 ndo94 = {0};
    struct pcap_pkthdr_b94 h94 = {.len = sym_len, .caplen = sym_caplen};

    /* Bug 96 structures */
    netdissect_options_b96 ndo96 = {0};

    /* Call both with SAME shared input */
    int r94 = cip_if_print(&ndo94, &h94, buf);
    int r96 = babel_print(&ndo96, buf, sym_len);

    /* Only keep paths where BOTH vulnerable branches were reached */
    klee_assume(r94 == 1);
    klee_assume(r96 == 1);

    /* Force KLEE to materialize a concrete test case satisfying both */
    klee_assert(0 && "REACHED_BOTH_VULNERABLE_PATHS_94_96");

    free(buf);
    return 0;
}