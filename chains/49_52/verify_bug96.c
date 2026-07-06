#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

typedef struct netdissect_options_b96 {
    int dummy;
} netdissect_options_b96;

extern int babel_print(netdissect_options_b96 *ndo, const u_char *cp, u_int length);

int main(void) {
    printf("[BUG 96] Testing with SHARED INPUT: buf=zeros, len=97\n");
    
    unsigned char *buf = calloc(1, 512);
    memset(buf, 0, 512);
    
    netdissect_options_b96 ndo96 = {0};
    
    babel_print(&ndo96, buf, 97);
    
    printf("[!] UNREACHED\n");
    free(buf);
    return 0;
}