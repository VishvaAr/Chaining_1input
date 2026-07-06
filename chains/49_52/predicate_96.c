#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <klee/klee.h>

#define BUF_SIZE 512

typedef struct netdissect_options_b96 {
    int dummy;
} netdissect_options_b96;

/* Predicate: returns 1 if vulnerable path reached, 0 otherwise */
static const char *format_prefix(netdissect_options_b96 *ndo, 
                                 const u_char *prefix, unsigned char plen)
{
    static char buf[50];
    
    /* Bounds check */
    if ((uintptr_t)prefix == 0) return NULL;
    
    /* Both branches access the prefix buffer */
    if (plen >= 96) {
        snprintf(buf, 50, "%u", plen - 96);
        (void)prefix[12];  /* Access at offset 12 */
    } else {
        snprintf(buf, 50, "%u", plen);
        (void)prefix[0];   /* Access at offset 0 */
    }
    
    return buf;
}

int babel_print(netdissect_options_b96 *ndo, const u_char *cp, u_int length)
{
    /* Guards: must reach vulnerable format_prefix */
    if (length < 6) return 0;
    if ((uintptr_t)cp == 0) return 0;
    if (length > BUF_SIZE) return 0;
    
    /* Call vulnerable function */
    format_prefix(ndo, cp, length);
    
    /* Return 1: vulnerable path reached */
    return 1;
}