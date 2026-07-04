/* predicate_94.c — non-crashing twin of CIP parser for joint-satisfiability search */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef struct netdissect_options {
    int ndo_eflag;
    int ndo_suppress_default_print;
} netdissect_options;

struct pcap_pkthdr {
    uint32_t len;
    uint32_t caplen;
};

#define BUF_SIZE 512

static void cip_print(netdissect_options *ndo, u_int length) { (void)ndo; (void)length; }
static int llc_print(netdissect_options *ndo, const u_char *p, u_int length, u_int caplen, void *a, void *b) {
    (void)ndo; (void)p; (void)length; (void)caplen; (void)a; (void)b; return -1;
}
static void ip_print(netdissect_options *ndo, const u_char *p, u_int length) { (void)ndo; (void)p; (void)length; }

int cip_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
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
        return 0;  /* couldn't reach vulnerable path */
    }
    
    /* The vulnerable branch: memcmp checks first 6 bytes, then calls ip_print
       which is the sink. Both branches converge at ip_print call. */
    if (memcmp("\xAA\xAA\x03\x00\x00\x00", p, cmplen) == 0) {
        llc_hdrlen = llc_print(ndo, p, length, caplen, NULL, NULL);
        if (llc_hdrlen < 0) {
            if (!ndo->ndo_suppress_default_print)
                ;  /* ND_DEFAULTPRINT would happen here */
            llc_hdrlen = -llc_hdrlen;
        }
    } else {
        llc_hdrlen = 0;
    }
    
    /* Both branches converge here and hit ip_print (the sink in original code) */
    ip_print(ndo, p, length);
    
    /* In original: klee_assert(0 && "SAILOR_SINK_REACHED");
       In predicate: return 1 to signal we reached the vulnerable path */
    return 1;
}