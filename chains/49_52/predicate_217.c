#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

/* MUST match driver's struct definition exactly */
typedef struct netdissect_options {
    const u_char *ndo_snapend;
    int ndo_vflag;
} netdissect_options;

#define ND_PRINT(x) do { } while (0)
#define ND_TCHECK(x) do { } while (0)

/* Function name MUST match what driver expects */
int dvmrp_print_predicate_217(netdissect_options *ndo,
                              register const u_char *bp, 
                              register u_int len)
{
    klee_warning_once("SPINE_PROBE:dvmrp_print_predicate_217:ENTRY");
    register const u_char *ep;
    register u_char type;
    
    ep = (const u_char *)ndo->ndo_snapend;
    if (bp >= ep)
        return 0;  /* Early exit - didn't reach vulnerable path */
    
    /* Bounds check before accessing bp[1] */
    if (bp + 1 >= ep)
        return 0;
    
    type = bp[1];
    
    /* Skip IGMP header - but only if we have room */
    if (bp + 8 > ep || len < 8)
        return 0;
    
    bp += 8;
    len -= 8;
    
    switch (type) {
    case 0:
        klee_warning_once("SPINE_PROBE:dvmrp_print_predicate_217:CASE_0");
        ND_PRINT((ndo, " Probe"));
        if (ndo->ndo_vflag) {
            break;
        }
        break;
    case 1:
        klee_warning_once("SPINE_PROBE:dvmrp_print_predicate_217:CASE_1");
        ND_PRINT((ndo, " Report"));
        if (ndo->ndo_vflag > 1) {
            break;
        }
        break;
    default:
        break;
    }
    
    /* Reached vulnerable sink - return 1 to signal success */
    return 1;
}