#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef struct netdissect_options {
    int dummy;
} netdissect_options;

/* Real bug 96 entry point from print-babel.c with original klee_assert */
extern void babel_print(netdissect_options *ndo, const u_char *cp, u_int length);

int main(void) {
    netdissect_options *ndo = (netdissect_options *)calloc(1, sizeof(*ndo));
    unsigned char *buf = (unsigned char *)calloc(512, 1);
    
    /* Concrete values from KLEE's shared input */
    memset(buf, 0, 512);  /* all zeros */
    u_int len = 97;
    
    /* Call real bug 96 with this concrete input */
    printf("Calling babel_print with len=97, buf=all-zeros...\n");
    babel_print(ndo, buf, len);
    
    printf("BUG 96 TRIGGERED!\n");
    return 0;
}
