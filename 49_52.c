// NO_HARNESS_TYPES
// Chained harness for bug 49 + bug 52
//
// Both original drivers call the exact same target function
// (ieee802_11_if_print) with the same argument shapes and the same
// 512-byte, fully-symbolic packet buffer. Because they share an entry
// point, they don't need to be invoked twice or sequenced — a single
// symbolic buffer handed to the function once is sufficient for KLEE
// to fork across every branch reachable from that call, including the
// code paths responsible for bug 49 and bug 52, within the same run.
//
// If you ever need to chain two *different* target functions (not the
// case here), the pattern is: derive two independently-constrained
// buffers/regions from one symbolic input, call target A on region 1,
// then (only if target A doesn't abort the process on error) call
// target B on region 2. For a single shared function like this one,
// that split is unnecessary and would only fragment the symbolic
// input the solver has to work with.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

typedef struct pcap_pkthdr {
    uint32_t len;
    uint32_t caplen;
} pcap_pkthdr;

typedef struct netdissect_options {
    int dummy;
} netdissect_options;

#ifndef MAX_MCS_INDEX
#define MAX_MCS_INDEX 76
#endif

extern u_int ieee802_11_if_print(netdissect_options *ndo,
                                  const struct pcap_pkthdr *h,
                                  const u_char *p);

int main(void) {
    netdissect_options *ndo = (netdissect_options *)calloc(1, sizeof(netdissect_options));
    struct pcap_pkthdr *h = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
    unsigned char *buf = (unsigned char *)calloc(1, 512);

    klee_make_symbolic(buf, 512, "buf");

    h->len = 512;
    h->caplen = 512;

    // Single call, single symbolic input. KLEE's path exploration
    // from this one call site is what surfaces both bug 49's and
    // bug 52's crashing paths within the same run.
    ieee802_11_if_print(ndo, h, buf);

    free(buf);
    free(h);
    free(ndo);
    return 0;
}
