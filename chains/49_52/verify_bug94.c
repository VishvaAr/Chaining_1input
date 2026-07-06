#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char u_char;

typedef struct netdissect_options_b94 {
    int ndo_eflag;
    int ndo_suppress_default_print;
} netdissect_options_b94;

struct pcap_pkthdr_b94 {
    uint32_t len;
    uint32_t caplen;
};

extern int cip_if_print(netdissect_options_b94 *ndo,
                        const struct pcap_pkthdr_b94 *h, const u_char *p);

int main(void) {
    printf("[BUG 94] Testing with SHARED INPUT: buf=zeros, len=97, caplen=97\n");
    
    unsigned char *buf = calloc(1, 512);
    memset(buf, 0, 512);
    
    netdissect_options_b94 ndo94 = {0};
    struct pcap_pkthdr_b94 h94 = {.len = 97, .caplen = 97};
    
    cip_if_print(&ndo94, &h94, buf);
    
    printf("[!] UNREACHED\n");
    free(buf);
    return 0;
}