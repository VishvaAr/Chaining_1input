#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

/* MUST match driver's struct definition exactly - SIMPLIFIED */
typedef struct netdissect_options {
    const u_char *ndo_snapend;
    int ndo_vflag;
} netdissect_options;

/* Function name MUST match what driver expects */
int dvmrp_print_predicate_219(netdissect_options *ndo,
                              register const u_char *bp, 
                              register u_int len)
{
    klee_warning_once("SPINE_PROBE:dvmrp_print_predicate_219:ENTRY");
    register const u_char *ep;
    register u_char type;
    
    ep = (const u_char *)ndo->ndo_snapend;
    if (bp >= ep)
        return 0;  /* Early exit - didn't reach vulnerable path */
    
    /* Bounds check before accessing bp[1] */
    if (bp + 1 >= ep)
        return 0;
    
    type = bp[1];
    
    /* Bug 219 has two unconditional asserts right here
       Both indicate vulnerability reached - return 1 */
    return 1;
}