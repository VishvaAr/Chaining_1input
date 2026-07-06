#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

typedef struct netdissect_options {
    const u_char *ndo_snapend;
    int ndo_vflag;
} netdissect_options;

extern void dvmrp_print(netdissect_options *ndo, const u_char *bp, u_int len);

int main(void) {
    printf("[BUG 219] Testing with SHARED INPUT: buf=zeros, len=8, vflag=0\n");
    
    u_char buf[512];
    memset(buf, 0, 512);
    
    netdissect_options ndo = {0};
    ndo.ndo_snapend = buf + 8;
    ndo.ndo_vflag = 0;
    
    dvmrp_print(&ndo, buf, 8);
    
    printf("[!] UNREACHED\n");
    return 0;
}
