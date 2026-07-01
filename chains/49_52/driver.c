#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>

/* Chained harness for bug 49 + bug 52.
 *
 * IMPORTANT DESIGN NOTE:
 * Both bugs' sinks (klee_assert(0 ...)) are unconditional once their
 * respective parse_elements_bXX function is reached — they are not
 * gated on symbolic data. klee_assert terminates the current KLEE
 * state on failure. That means if this driver just called both
 * entry points back-to-back in one main(), the FIRST call would end
 * every execution state before the second call ever ran, and you'd
 * only ever observe one bug from this binary, never both.
 *
 * To get both bugs to surface from a single KLEE invocation, the
 * choice of which spine to call is itself made symbolic (driven by
 * one byte of the shared symbolic input). KLEE will fork into two
 * states at that branch — one that calls spine_49 and hits
 * SAILOR_SINK_REACHED_B49, and one that calls spine_52 and hits
 * SAILOR_SINK_REACHED_B52 — both discovered in the same run.
 *
 * This is the correct interpretation of "one input triggers both
 * bugs in one run" for sinks that are unconditional per-call: the
 * single symbolic input space covers both, even though any one
 * concrete test case only ever exercises one spine.
 */

typedef unsigned char u_char;
typedef unsigned int u_int;

/* --- bug 49 types (from spine_49.c) --- */
typedef struct pcap_pkthdr_b49 {
    uint32_t len;
    uint32_t caplen;
} pcap_pkthdr_b49;
typedef struct netdissect_options_b49 {
    int dummy;
} netdissect_options_b49;

/* --- bug 52 types (from spine_52.c) --- */
struct timeval_b52 { long tv_sec; long tv_usec; };
struct pcap_pkthdr_b52 {
    struct timeval_b52 ts;
    uint32_t caplen;
    uint32_t len;
};
struct netdissect_options_b52 {
  int ndo_bflag; int ndo_eflag; int ndo_fflag; int ndo_Kflag; int ndo_nflag;
  int ndo_Nflag; int ndo_qflag; int ndo_Sflag; int ndo_tflag; int ndo_uflag;
  int ndo_vflag;
};

extern u_int ieee802_11_if_print_b49(netdissect_options_b49 *ndo,
                    const struct pcap_pkthdr_b49 *h, const u_char *p);
extern u_int ieee802_11_if_print_b52(struct netdissect_options_b52 *ndo,
                    const struct pcap_pkthdr_b52 *h, const u_char *p);

int main(void) {
    /* One shared symbolic packet buffer, as in both original drivers */
    unsigned char *buf = (unsigned char *)calloc(1, 512);
    klee_make_symbolic(buf, 512, "buf");

    /* One symbolic selector byte determines which spine runs on this
     * path. It's carved out of a separate symbolic object rather than
     * reusing buf[0], so it doesn't perturb the packet-parsing bytes
     * each spine actually reads from offset 0. */
    unsigned char selector;
    klee_make_symbolic(&selector, sizeof(selector), "spine_selector");

    if (selector & 1) {
        /* ---- Path A: bug 49 ---- */
        netdissect_options_b49 *ndo49 = (netdissect_options_b49 *)calloc(1, sizeof(*ndo49));
        pcap_pkthdr_b49 *h49 = (pcap_pkthdr_b49 *)calloc(1, sizeof(*h49));
        h49->len = 512;
        h49->caplen = 512;
        ieee802_11_if_print_b49(ndo49, h49, buf);
        free(h49);
        free(ndo49);
    } else {
        /* ---- Path B: bug 52 ---- */
        struct netdissect_options_b52 *ndo52 = (struct netdissect_options_b52 *)calloc(1, sizeof(*ndo52));
        struct pcap_pkthdr_b52 *h52 = (struct pcap_pkthdr_b52 *)calloc(1, sizeof(*h52));
        h52->len = 512;
        h52->caplen = 512;
        ieee802_11_if_print_b52(ndo52, h52, buf);
        free(h52);
        free(ndo52);
    }

    free(buf);
    return 0;
}
