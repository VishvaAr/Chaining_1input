/* spine_52.c — bug 52's spine, with externally-linked entry points
 * renamed with a _b52 suffix so it can coexist with spine_49.c in the
 * same bitcode module without symbol collisions. Body is otherwise
 * IDENTICAL to the original print-802_11.c for bug 52 — do not change
 * the vulnerable memcpy/offset logic, only the four public names.
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

/* Bug 52's original driver pulled pcap_pkthdr from real <pcap.h>.
 * We keep an explicit local struct here instead, matching real
 * <pcap.h> field order (ts, caplen, len), so this file has no
 * external header dependency and no symbol/type collision risk
 * with spine_49.c's pcap_pkthdr_b49. Adjust field order/types here
 * if your actual <pcap.h> differs. */
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

static int parse_elements_b52(struct netdissect_options_b52 *ndo,
               struct mgmt_body_t_b52 *pbody, const u_char *p, int offset,
               u_int length)
{
    klee_warning_once("SPINE_PROBE:parse_elements_b52:ENTRY");
    u_int elementlen;
    struct tim_t_b52 tim;
    while (length > 0) {
        switch (*(p + offset)) {
        default:
            offset += 2 + elementlen;
            length -= 2 + elementlen;
            break;
        case 5:
            klee_warning_once("SPINE_PROBE:parse_elements_b52:CASE_5");
            memcpy(&tim, p + offset, 2);
            offset += 2;
            length -= 2;
            if (tim.length <= 3) {
                offset += tim.length;
                length -= tim.length;
                break;
            }
            if (tim.length - 3 > (int)sizeof tim.bitmap)
                return 0;
            memcpy(&tim.count, p + offset, 3);
            offset += 3;
            length -= 3;
            memcpy(tim.bitmap, p + offset, tim.length - 3);
            offset += tim.length - 3;
            length -= tim.length - 3;
            if (!pbody->tim_present) {
                pbody->tim = tim;
                pbody->tim_present = 1;
            }
            break;
        }
    }
    klee_assert(0 && "SAILOR_SINK_REACHED_B52");
    return 1;
}

void handle_beacon_b52(struct netdissect_options_b52 *ndo, const u_char *p, u_int len, u_int caplen, int arg1, int arg2) {
    struct mgmt_body_t_b52 body;
    memset(&body, 0, sizeof(body));
    parse_elements_b52(ndo, &body, p, 0, len);
    klee_warning_once("SPINE_PROBE:handle_beacon_b52:ENTRY");
}

void mgmt_body_print_b52(struct netdissect_options_b52 *ndo, const u_char *p, u_int len, u_int caplen, int arg1, int arg2) {
    handle_beacon_b52(ndo, p, len, caplen, arg1, arg2);
    klee_warning_once("SPINE_PROBE:mgmt_body_print_b52:ENTRY");
}

u_int ieee802_11_print_b52(struct netdissect_options_b52 *ndo, const u_char *p, u_int len, u_int caplen, int arg1, int arg2) {
    mgmt_body_print_b52(ndo, p, len, caplen, arg1, arg2);
    klee_warning_once("SPINE_PROBE:ieee802_11_print_b52:ENTRY");
    return 0;
}

u_int ieee802_11_if_print_b52(struct netdissect_options_b52 *ndo,
                    const struct pcap_pkthdr_b52 *h, const u_char *p)
{
    klee_warning_once("SPINE_PROBE:ieee802_11_if_print_b52:ENTRY");
    return ieee802_11_print_b52(ndo, p, h->len, h->caplen, 0, 0);
}
