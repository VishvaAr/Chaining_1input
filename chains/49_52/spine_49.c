/* spine_49.c — bug 49's spine, with externally-linked entry points
 * renamed with a _b49 suffix so it can coexist with spine_52.c in the
 * same bitcode module without symbol collisions. Body is otherwise
 * IDENTICAL to the original print-802_11.c for bug 49 — do not change
 * the vulnerable memcpy/offset logic, only the four public names.
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
struct ssid_t_b49 { int dummy; };
struct challenge_t_b49 { int dummy; };
struct rates_t_b49 { int dummy; };
struct ds_t_b49 { int dummy; };
struct tim_t_b49 { int dummy; };

#ifndef E_CF
#define E_CF 1
#endif

static int parse_elements_b49(netdissect_options_b49 *ndo,
               struct mgmt_body_t_b49 *pbody, const u_char *p, int offset,
               u_int length)
{
    klee_warning_once("SPINE_PROBE:parse_elements_b49:ENTRY");
    u_int elementlen;
    struct ssid_t_b49 ssid;
    struct challenge_t_b49 challenge;
    struct rates_t_b49 rates;
    struct ds_t_b49 ds;
    struct cf_t_b49 cf;
    struct tim_t_b49 tim;
    switch (pbody->element) {
    default:
        break;
    case E_CF:
        klee_warning_once("SPINE_PROBE:parse_elements_b49:CASE_E_CF");
        memcpy(&cf, p + offset, 2);
        offset += 2;
        length -= 2;
        if (cf.length != 6) {
            offset += cf.length;
            length -= cf.length;
            break;
        }
        memcpy(&cf.count, p + offset, 6);
        offset += 6;
        length -= 6;
        if (!pbody->cf_present) {
            pbody->cf = cf;
            pbody->cf_present = 1;
        }
        break;
    }
    klee_assert(0 && "SAILOR_SINK_REACHED_B49");
    return 1;
}

void handle_beacon_b49(netdissect_options_b49 *ndo, const u_char *p, u_int len, u_int caplen, int a, int b) {
    klee_warning_once("SPINE_PROBE:handle_beacon_b49:ENTRY");
    struct mgmt_body_t_b49 *pbody = (struct mgmt_body_t_b49 *)calloc(1, sizeof(struct mgmt_body_t_b49));
    pbody->element = E_CF;
    parse_elements_b49(ndo, pbody, p, 0, 2);
}

void mgmt_body_print_b49(netdissect_options_b49 *ndo, const u_char *p, u_int len, u_int caplen, int a, int b) {
    handle_beacon_b49(ndo, p, len, caplen, a, b);
    klee_warning_once("SPINE_PROBE:mgmt_body_print_b49:ENTRY");
}

u_int ieee802_11_print_b49(netdissect_options_b49 *ndo, const u_char *p, u_int len, u_int caplen, int a, int b)
{
    mgmt_body_print_b49(ndo, p, len, caplen, a, b);
    klee_warning_once("SPINE_PROBE:ieee802_11_print_b49:ENTRY");
    struct mgmt_body_t_b49 *pbody = (struct mgmt_body_t_b49 *)calloc(1, sizeof(struct mgmt_body_t_b49));
    pbody->element = E_CF;
    return parse_elements_b49(ndo, pbody, p, 0, len);
}

u_int ieee802_11_if_print_b49(netdissect_options_b49 *ndo,
                    const struct pcap_pkthdr_b49 *h, const u_char *p)
{
    klee_warning_once("SPINE_PROBE:ieee802_11_if_print_b49:ENTRY");
    return ieee802_11_print_b49(ndo, p, h->len, h->caplen, 0, 0);
}
