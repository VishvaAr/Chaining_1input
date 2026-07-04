#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef struct netdissect_options {
    int ndo_eflag;
    int ndo_suppress_default_print;
} netdissect_options;

#define ND_DEFAULTPRINT(p, l) do { (void)(p); (void)(l); } while (0)
#define ND_PRINT(x) do { } while (0)

struct pcap_pkthdr {
    uint32_t len;
    uint32_t caplen;
};

static void cip_print(netdissect_options *ndo, u_int length) { (void)ndo; (void)length; }
static int llc_print(netdissect_options *ndo, const u_char *p, u_int length, u_int caplen, void *a, void *b) {
    (void)ndo; (void)p; (void)length; (void)caplen; (void)a; (void)b; return -1;
}
static void ip_print(netdissect_options *ndo, const u_char *p, u_int length) { (void)ndo; (void)p; (void)length; }

u_int cip_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
    klee_warning_once("SPINE_PROBE:cip_if_print:ENTRY");
    u_int caplen = h->caplen;
    u_int length = h->len;
    size_t cmplen;
    int llc_hdrlen;
    cmplen = 6;
    if (cmplen > caplen)
        cmplen = caplen;
    if (cmplen > length)
        cmplen = length;
    if (ndo->ndo_eflag)
        cip_print(ndo, length);
    if (cmplen == 0) {
        ND_PRINT((ndo, "[|cip]"));
        return 0;
    }
    if (memcmp("\xAA\xAA\x03\x00\x00\x00", p, cmplen) == 0) {
        llc_hdrlen = llc_print(ndo, p, length, caplen, NULL, NULL);
        if (llc_hdrlen < 0) {
            if (!ndo->ndo_suppress_default_print)
                ND_DEFAULTPRINT(p, caplen);
            llc_hdrlen = -llc_hdrlen;
        }
    } else {
        llc_hdrlen = 0;
        ip_print(ndo, p, length);
    }
    klee_assert(0 && "SAILOR_SINK_REACHED_BUG94");
    return (llc_hdrlen);
}