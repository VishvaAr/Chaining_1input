#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

typedef struct pcap_pkthdr_b49 { uint32_t len; uint32_t caplen; } pcap_pkthdr_b49;
typedef struct netdissect_options_b49 { int dummy; } netdissect_options_b49;

struct timeval_b52 { long tv_sec; long tv_usec; };
struct pcap_pkthdr_b52 { struct timeval_b52 ts; uint32_t caplen; uint32_t len; };
struct netdissect_options_b52 {
  int ndo_bflag; int ndo_eflag; int ndo_fflag; int ndo_Kflag; int ndo_nflag;
  int ndo_Nflag; int ndo_qflag; int ndo_Sflag; int ndo_tflag; int ndo_uflag;
  int ndo_vflag;
};

/* These match the ACTUAL int-returning names defined in predicate_49.c / predicate_52.c */
extern int ieee802_11_if_print_b49(netdissect_options_b49 *ndo,
                    const pcap_pkthdr_b49 *h, const u_char *p);
extern int ieee802_11_if_print_b52(struct netdissect_options_b52 *ndo,
                    const struct pcap_pkthdr_b52 *h, const u_char *p);

int main(void) {
    unsigned char *buf = calloc(1, 512);
    klee_make_symbolic(buf, 512, "buf");

    uint32_t sym_len, sym_caplen;
    klee_make_symbolic(&sym_len, sizeof(sym_len), "len");
    klee_make_symbolic(&sym_caplen, sizeof(sym_caplen), "caplen");
    klee_assume(sym_caplen <= 512);
    klee_assume(sym_len >= sym_caplen);

    pcap_pkthdr_b49 h49 = {.len = sym_len, .caplen = sym_caplen};
    struct pcap_pkthdr_b52 h52 = {.ts = {0,0}, .len = sym_len, .caplen = sym_caplen};
    netdissect_options_b49 ndo49 = {0};
    struct netdissect_options_b52 ndo52 = {0};

    /* SAME buf, SAME sym_len, SAME sym_caplen fed to both — no crash yet,
       just "did we reach the vulnerable branch" signals */
    int r49 = ieee802_11_if_print_b49(&ndo49, &h49, buf);
    int r52 = ieee802_11_if_print_b52(&ndo52, &h52, buf);

    /* Only keep states where BOTH vulnerable branches were reached
       on THIS SAME shared input */
    klee_assume(r49 == 1);
    klee_assume(r52 == 1);

    /* Force KLEE to materialize a concrete test case satisfying both */
    klee_assert(0 && "REACHED_BOTH_VULNERABLE_PATHS");

    return 0;
}