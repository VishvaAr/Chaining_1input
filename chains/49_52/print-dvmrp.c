/* print-dvmrp.c — Real buggy code with klee_assert(0) sinks for both bugs 217 and 219 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

typedef struct netdissect_options {
    int ndo_bflag;
    int ndo_eflag;
    int ndo_fflag;
    int ndo_Kflag;
    int ndo_nflag;
    int ndo_Nflag;
    int ndo_qflag;
    int ndo_Sflag;
    int ndo_tflag;
    int ndo_uflag;
    int ndo_vflag;
    int ndo_xflag;
    int ndo_Xflag;
    int ndo_Aflag;
    void *ndo_snapend;
} netdissect_options;

#define DVMRP_PROBE 1
#define DVMRP_REPORT 2
#define DVMRP_ASK_NEIGHBORS 3
#define DVMRP_NEIGHBORS 4
#define DVMRP_ASK_NEIGHBORS2 5
#define DVMRP_NEIGHBORS2 6
#define DVMRP_PRUNE 7
#define DVMRP_GRAFT 8
#define DVMRP_GRAFT_ACK 9

static uint32_t target_level;
static int print_probe(netdissect_options *ndo, const u_char *bp, const u_char *ep, u_int len) { return 0; }
static int print_report(netdissect_options *ndo, const u_char *bp, const u_char *ep, u_int len) { return 0; }
static int print_neighbors(netdissect_options *ndo, const u_char *bp, const u_char *ep, u_int len) { return 0; }
static int print_neighbors2(netdissect_options *ndo, const u_char *bp, const u_char *ep, u_int len) { return 0; }
static int print_prune(netdissect_options *ndo, const u_char *bp) { return 0; }
static int print_graft(netdissect_options *ndo, const u_char *bp) { return 0; }
static int print_graft_ack(netdissect_options *ndo, const u_char *bp) { return 0; }

void dvmrp_print(netdissect_options *ndo, register const u_char *bp, register u_int len)
{
    klee_warning_once("SPINE_PROBE:dvmrp_print:ENTRY");
    register const u_char *ep;
    register u_char type;
    
    ep = (const u_char *)ndo->ndo_snapend;
    if (bp >= ep)
        return;
    
    type = bp[1];
    
    /* BUG 219: Two unconditional klee_assert(0) statements */
    klee_assert(0 && "SAILOR_SINK_REACHED_BUG219");
    klee_assert(0 && "SAILOR_SINK_REACHED_BUG219");
    
    /* Skip IGMP header */
    bp += 8;
    len -= 8;
    
    switch (type) {
    case DVMRP_PROBE:
        klee_warning_once("SPINE_PROBE:dvmrp_print:CASE_DVMRP_PROBE");
        if (ndo->ndo_vflag) {
            if (print_probe(ndo, bp, ep, len) < 0)
                goto trunc;
        }
        break;
    case DVMRP_REPORT:
        klee_warning_once("SPINE_PROBE:dvmrp_print:CASE_DVMRP_REPORT");
        if (ndo->ndo_vflag > 1) {
            if (print_report(ndo, bp, ep, len) < 0)
                goto trunc;
        }
        break;
    case DVMRP_ASK_NEIGHBORS:
        break;
    case DVMRP_NEIGHBORS:
        klee_warning_once("SPINE_PROBE:dvmrp_print:CASE_DVMRP_NEIGHBORS");
        if (print_neighbors(ndo, bp, ep, len) < 0)
            goto trunc;
        break;
    case DVMRP_ASK_NEIGHBORS2:
        break;
    case DVMRP_NEIGHBORS2:
        klee_warning_once("SPINE_PROBE:dvmrp_print:CASE_DVMRP_NEIGHBORS2");
        bp -= 4;
        target_level = (bp[0] << 24) | (bp[1] << 16) | (bp[2] << 8) | bp[3];
        bp += 4;
        if (print_neighbors2(ndo, bp, ep, len) < 0)
            goto trunc;
        break;
    case DVMRP_PRUNE:
        klee_warning_once("SPINE_PROBE:dvmrp_print:CASE_DVMRP_PRUNE");
        if (print_prune(ndo, bp) < 0)
            goto trunc;
        break;
    case DVMRP_GRAFT:
        klee_warning_once("SPINE_PROBE:dvmrp_print:CASE_DVMRP_GRAFT");
        if (print_graft(ndo, bp) < 0)
            goto trunc;
        break;
    case DVMRP_GRAFT_ACK:
        klee_warning_once("SPINE_PROBE:dvmrp_print:CASE_DVMRP_GRAFT_ACK");
        if (print_graft_ack(ndo, bp) < 0)
            goto trunc;
        break;
    default:
        break;
    }
    return;
trunc:
    klee_warning_once("SPINE_PROBE:dvmrp_print:LABEL_trunc");
    klee_assert(0 && "SAILOR_SINK_REACHED_BUG217");
    return;
}
