/* predicate_52.c — non-crashing twin of spine_52.c for KLEE-based
 * joint-satisfiability search. Vulnerable memcpy/offset logic is
 * IDENTICAL to the original, plus explicit bounds checks so KLEE's
 * own out-of-bounds detector doesn't fire on the ORIGINAL bug's
 * uninitialized `elementlen` in the default case (a real latent bug
 * in upstream tcpdump, not something introduced here) before we can
 * even evaluate the branch we actually care about.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <klee/klee.h>

#ifndef MAX_MCS_INDEX
#define MAX_MCS_INDEX 76
#endif

typedef unsigned char u_char;
typedef unsigned int u_int;

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

struct tim_t_b52 {
    u_char id;
    u_char length;
    u_char count;
    u_char period;
    u_char bitmap[256];
};

struct mgmt_body_t_b52 {
    int tim_present;
    struct tim_t_b52 tim;
};

#define BUF_SIZE_B52 512   /* must match calloc size in driver.c */

static int parse_elements_b52(struct netdissect_options_b52 *ndo,
               struct mgmt_body_t_b52 *pbody, const u_char *p, int offset,
               u_int length)
{
    klee_warning_once("SPINE_PROBE:parse_elements_b52:ENTRY");
    struct tim_t_b52 tim;

    while (length > 0) {
        if (offset < 0 || (u_int)offset >= BUF_SIZE_B52)
            return 0;   /* stop before reading out of bounds */

        switch (*(p + offset)) {
        default:
            /* Original upstream code has an uninitialized `elementlen`
               read here. This branch never reaches the vulnerable
               tim.bitmap memcpy anyway, so bail out cleanly instead
               of reproducing that separate, unrelated bug. */
            return 0;
        case 5:
            klee_warning_once("SPINE_PROBE:parse_elements_b52:CASE_5");
            if ((u_int)offset + 2 > BUF_SIZE_B52)
                return 0;
            memcpy(&tim, p + offset, 2);
            offset += 2;
            length -= 2;
            if (tim.length <= 3) {
                return 0;   /* doesn't reach the vulnerable branch */
            }
            if (tim.length - 3 > (int)sizeof tim.bitmap)
                return 0;   /* original code's own bounds check */
            if ((u_int)offset + 3 > BUF_SIZE_B52)
                return 0;
            memcpy(&tim.count, p + offset, 3);
            offset += 3;
            length -= 3;
            if ((u_int)offset + (tim.length - 3) > BUF_SIZE_B52)
                return 0;
            memcpy(tim.bitmap, p + offset, tim.length - 3);
            offset += tim.length - 3;
            length -= tim.length - 3;
            if (!pbody->tim_present) {
                pbody->tim = tim;
                pbody->tim_present = 1;
            }
            return 1;   /* reached the actual vulnerable memcpy */
        }
    }
    return 0;   /* loop exited without reaching case 5's vulnerable path */
}

int handle_beacon_b52(struct netdissect_options_b52 *ndo, const u_char *p, u_int len, u_int caplen, int arg1, int arg2) {
    struct mgmt_body_t_b52 body;
    memset(&body, 0, sizeof(body));
    klee_warning_once("SPINE_PROBE:handle_beacon_b52:ENTRY");
    return parse_elements_b52(ndo, &body, p, 0, len);
}

int mgmt_body_print_b52(struct netdissect_options_b52 *ndo, const u_char *p, u_int len, u_int caplen, int arg1, int arg2) {
    klee_warning_once("SPINE_PROBE:mgmt_body_print_b52:ENTRY");
    return handle_beacon_b52(ndo, p, len, caplen, arg1, arg2);
}

int ieee802_11_print_b52(struct netdissect_options_b52 *ndo, const u_char *p, u_int len, u_int caplen, int arg1, int arg2) {
    klee_warning_once("SPINE_PROBE:ieee802_11_print_b52:ENTRY");
    return mgmt_body_print_b52(ndo, p, len, caplen, arg1, arg2);
}

int ieee802_11_if_print_b52(struct netdissect_options_b52 *ndo,
                    const struct pcap_pkthdr_b52 *h, const u_char *p)
{
    klee_warning_once("SPINE_PROBE:ieee802_11_if_print_b52:ENTRY");
    return ieee802_11_print_b52(ndo, p, h->len, h->caplen, 0, 0);
}