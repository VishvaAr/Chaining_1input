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

/* Real bug 94 entry point from print-cip.c with original klee_assert */
extern u_int cip_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p);

int main(void) {
    netdissect_options *ndo = (netdissect_options *)calloc(1, sizeof(*ndo));
    struct pcap_pkthdr *h = (struct pcap_pkthdr *)calloc(1, sizeof(*h));
    unsigned char *buf = (unsigned char *)calloc(512, 1);
    
    /* Concrete values from KLEE's shared input */
    h->len = 97;
    h->caplen = 6;
    memset(buf, 0, 512);  /* all zeros */
    
    /* Call real bug 94 with this concrete input */
    printf("Calling cip_if_print with len=97, caplen=6, buf=all-zeros...\n");
    cip_if_print(ndo, h, buf);
    
    printf("BUG 94 TRIGGERED!\n");
    return 0;
}