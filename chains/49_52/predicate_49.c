/* predicate_49.c — non-crashing twin of spine_49.c for KLEE-based
 * joint-satisfiability search. Vulnerable memcpy/offset logic is
 * IDENTICAL to the original; only the sink and return values changed
 * so this reports "would it reach the vulnerable branch" instead of
 * actually asserting/crashing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

typedef struct pcap_pkthdr_b49 {
    uint32_t len;
    uint32_t caplen;
} pcap_pkthdr_b49;

typedef struct netdissect_options_b49 {
    int dummy;
} netdissect_options_b49;

struct cf_t_b49 { unsigned char length; unsigned char count[6]; };
struct mgmt_body_t_b49 { int element; int cf_present; struct cf_t_b49 cf; };

#ifndef E_CF
#define E_CF 1
#endif

#define BUF_SIZE_B49 512   /* must match calloc size in driver.c */

static int parse_elements_b49(netdissect_options_b49 *ndo,
               struct mgmt_body_t_b49 *pbody, const u_char *p, int offset,
               u_int length)
{
    klee_warning_once("SPINE_PROBE:parse_elements_b49:ENTRY");
    struct cf_t_b49 cf;

    switch (pbody->element) {
    default:
        return 0;   /* never reaches the vulnerable path */
    case E_CF:
        klee_warning_once("SPINE_PROBE:parse_elements_b49:CASE_E_CF");
        if (offset < 0 || (u_int)offset + 2 > BUF_SIZE_B49 || length < 2)
            return 0;
        memcpy(&cf, p + offset, 2);
        offset += 2;
        length -= 2;
        if (cf.length != 6) {
            return 0;   /* doesn't reach the vulnerable second memcpy */
        }
        if ((u_int)offset + 6 > BUF_SIZE_B49 || length < 6)
            return 0;
        memcpy(&cf.count, p + offset, 6);
        offset += 6;
        length -= 6;
        if (!pbody->cf_present) {
            pbody->cf = cf;
            pbody->cf_present = 1;
        }
        return 1;   /* reached the actual vulnerable branch */
    }
}

int handle_beacon_b49(netdissect_options_b49 *ndo, const u_char *p, u_int len, u_int caplen, int a, int b) {
    klee_warning_once("SPINE_PROBE:handle_beacon_b49:ENTRY");
    struct mgmt_body_t_b49 *pbody = (struct mgmt_body_t_b49 *)calloc(1, sizeof(struct mgmt_body_t_b49));
    pbody->element = E_CF;
    return parse_elements_b49(ndo, pbody, p, 0, 2);
}

int mgmt_body_print_b49(netdissect_options_b49 *ndo, const u_char *p, u_int len, u_int caplen, int a, int b) {
    klee_warning_once("SPINE_PROBE:mgmt_body_print_b49:ENTRY");
    return handle_beacon_b49(ndo, p, len, caplen, a, b);
}

int ieee802_11_print_b49(netdissect_options_b49 *ndo, const u_char *p, u_int len, u_int caplen, int a, int b)
{
    klee_warning_once("SPINE_PROBE:ieee802_11_print_b49:ENTRY");
    mgmt_body_print_b49(ndo, p, len, caplen, a, b);  /* discarded — matches original control flow */
    struct mgmt_body_t_b49 *pbody = (struct mgmt_body_t_b49 *)calloc(1, sizeof(struct mgmt_body_t_b49));
    pbody->element = E_CF;
    return parse_elements_b49(ndo, pbody, p, 0, len);
}

int ieee802_11_if_print_b49(netdissect_options_b49 *ndo,
                    const struct pcap_pkthdr_b49 *h, const u_char *p)
{
    klee_warning_once("SPINE_PROBE:ieee802_11_if_print_b49:ENTRY");
    return ieee802_11_print_b49(ndo, p, h->len, h->caplen, 0, 0);
}