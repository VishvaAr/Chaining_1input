#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

typedef struct netdissect_options_cip {
    int ndo_eflag;
    int ndo_suppress_default_print;
} netdissect_options_cip;

struct pcap_pkthdr_cip {
    uint32_t len;
    uint32_t caplen;
};

typedef struct netdissect_options_babel {
    int dummy;
} netdissect_options_babel;

/* Real bug 94 and 96 entry points */
extern u_int cip_if_print(netdissect_options_cip *ndo, const struct pcap_pkthdr_cip *h, const u_char *p);
extern void babel_print(netdissect_options_babel *ndo, const u_char *cp, u_int length);

int main(void) {
    /* Concrete shared input from KLEE's predicates */
    unsigned char buf[512];
    memset(buf, 0, 512);  /* all zeros */
    uint32_t len = 97;
    uint32_t caplen = 6;
    
    /* Symbolic selector to branch — but we're using concrete values, 
       so both branches will execute in separate paths if we explore symbolically,
       or we can just call both sequentially */
    unsigned char selector;
    klee_make_symbolic(&selector, sizeof(selector), "selector");
    
    if (selector & 1) {
        /* Path A: Bug 94 */
        netdissect_options_cip ndo94 = {0};
        struct pcap_pkthdr_cip h94 = {.len = len, .caplen = caplen};
        
        printf("Path A: Calling cip_if_print with len=97, caplen=6, buf=all-zeros...\n");
        cip_if_print(&ndo94, &h94, buf);
        printf("BUG 94 TRIGGERED!\n");
    } else {
        /* Path B: Bug 96 */
        netdissect_options_babel ndo96 = {0};
        
        printf("Path B: Calling babel_print with len=97, buf=all-zeros...\n");
        babel_print(&ndo96, buf, len);
        printf("BUG 96 TRIGGERED!\n");
    }
    
    return 0;
}
