#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

/* SINGLE struct type for both bugs */
typedef struct netdissect_options {
    const u_char *ndo_snapend;
    int ndo_vflag;
} netdissect_options;

extern int dvmrp_print_predicate_217(netdissect_options *ndo,
                                     register const u_char *bp, 
                                     register u_int len);
extern int dvmrp_print_predicate_219(netdissect_options *ndo,
                                     register const u_char *bp, 
                                     register u_int len);

int main(void) {
    /* LARGER shared symbolic buffer */
    u_char *buf = (u_char *)calloc(1, 512);
    klee_make_symbolic(buf, 512, "buf");
    
    /* SYMBOLIC len (not hardcoded) */
    u_int sym_len;
    klee_make_symbolic(&sym_len, sizeof(sym_len), "len");
    
    /* Narrow search space */
    klee_assume(sym_len >= 8);   /* DVMRP header is 8 bytes */
    klee_assume(sym_len <= 512);
    
    /* ONE shared symbolic snapend */
    const u_char *sym_snapend = buf + sym_len;
    
    /* ONE shared symbolic vflag */
    int sym_vflag;
    klee_make_symbolic(&sym_vflag, sizeof(sym_vflag), "vflag");
    
    /* ONE ndo structure - used by BOTH predicates */
    netdissect_options ndo = {0};
    ndo.ndo_snapend = sym_snapend;
    ndo.ndo_vflag = sym_vflag;
    
    /* Call BOTH predicates with IDENTICAL shared input */
    int r217 = dvmrp_print_predicate_217(&ndo, buf, sym_len);
    int r219 = dvmrp_print_predicate_219(&ndo, buf, sym_len);
    
    /* Require BOTH to reach vulnerable branches */
    klee_assume(r217 == 1);
    klee_assume(r219 == 1);
    
    /* Force KLEE to find shared input */
    klee_assert(0 && "REACHED_BOTH_VULNERABLE_PATHS_217_219");
    
    free(buf);
    return 0;
}