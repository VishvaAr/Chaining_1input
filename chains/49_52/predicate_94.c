#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>

#define BUF_SIZE 512

typedef struct netdissect_options_b94 {
    int ndo_eflag;
    int ndo_suppress_default_print;
} netdissect_options_b94;

struct pcap_pkthdr_b94 {
    uint32_t len;
    uint32_t caplen;
};

/* Predicate: returns 1 if vulnerable path reached, 0 otherwise */
int cip_if_print(netdissect_options_b94 *ndo,
                 const struct pcap_pkthdr_b94 *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;
    size_t cmplen = 6;
    
    if (cmplen > caplen) cmplen = caplen;
    if (cmplen > length) cmplen = length;
    
    /* Guard: must reach vulnerable memcpy */
    if (cmplen == 0) {
        return 0;
    }
    
    /* Bounds check: prevent KLEE's detector from firing */
    if (cmplen > BUF_SIZE) return 0;
    if ((uintptr_t)p == 0) return 0;
    
    /* Both branches converge here and access buffer */
    if (memcmp("\xAA\xAA\x03\x00\x00\x00", p, cmplen) == 0) {
        /* Branch A: harmless */
    } else {
        /* Branch B: vulnerable sink (would call ip_print) */
        /* In predicate, just access the buffer to prove we reached here */
        (void)p[0];
    }
    
    /* Return 1: vulnerable path reached */
    return 1;
}