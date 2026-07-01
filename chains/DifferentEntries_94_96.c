#include "harness_types.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <klee/klee.h>
 
// Chained harness for bug 94 + bug 96
//
// Unlike the ieee802_11_if_print case, these two bugs live in
// *different* target functions (cip_if_print vs. babel_print), so
// they can't share a single call site. Instead, all the symbolic
// objects each driver needs are created up front in the same main(),
// which makes them part of one unified symbolic input space for a
// single KLEE run. The two target calls are then made back-to-back,
// each reproducing its original driver's setup exactly (including
// which fields are concrete vs. symbolic), so the preconditions that
// trigger each bug are preserved.
//
// Caveat: if cip_if_print's bug causes the process to abort/terminate
// (e.g. a KLEE-detected OOB access that halts the path), babel_print
// will not execute on that particular path. That's expected and fine
// for a chained harness targeting two independent bugs in one run:
// KLEE will still explore the sibling paths where cip_if_print
// returns normally and continues on to exercise babel_print, and
// separately the paths where cip_if_print's own bug fires. Both bugs
// remain reachable within the same run.
 
int cip_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p);
int babel_print(netdissect_options *ndo, const unsigned char *buf, unsigned int length);
 
int main(void) {
    /* ---- Setup for cip_if_print (bug 94) ---- */
    netdissect_options *ndo1 = (netdissect_options *)calloc(1, sizeof(netdissect_options));
    struct pcap_pkthdr *h = (struct pcap_pkthdr *)calloc(1, sizeof(*h));
    u_char *p = (u_char *)malloc(4);
 
    klee_make_symbolic(ndo1, sizeof(*ndo1), "ndo1");
    klee_make_symbolic(h, sizeof(*h), "h");
    klee_make_symbolic(p, 4, "p");
 
    ndo1->ndo_eflag = 0;
    ndo1->ndo_suppress_default_print = 1;
    h->caplen = 6;
    h->len = 6;
 
    /* ---- Setup for babel_print (bug 96) ---- */
    netdissect_options *ndo2 = (netdissect_options *)calloc(1, sizeof(netdissect_options));
    unsigned char *buf = (unsigned char *)calloc(64, 1);
 
    klee_make_symbolic(buf, 64, "buf");
    buf[0] = 0;
    buf[1] = 0;
 
    /* ---- Chained calls, same run ---- */
    cip_if_print(ndo1, h, p);
    babel_print(ndo2, buf, 64);
 
    free(p);
    free(h);
    free(ndo1);
    free(buf);
    free(ndo2);
    return 0;
}
