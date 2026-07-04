int main(void) {
    unsigned char *buf = calloc(1, 512);
    klee_make_symbolic(buf, 512, "buf");

    /* ONE shared symbolic header fields */
    uint32_t sym_len, sym_caplen;
    klee_make_symbolic(&sym_len, sizeof(sym_len), "len");
    klee_make_symbolic(&sym_caplen, sizeof(sym_caplen), "caplen");
    
    /* Reasonable bounds */
    klee_assume(sym_caplen <= 512);
    klee_assume(sym_len >= sym_caplen);

    /* Build both headers from the SAME symbolic values */
    pcap_pkthdr_b49 h49 = {.len = sym_len, .caplen = sym_caplen};
    pcap_pkthdr_b52 h52 = {.ts = {0, 0}, .len = sym_len, .caplen = sym_caplen};

    /* ndo structs — still all-zero, they don't matter */
    netdissect_options_b49 ndo49 = {0};
    netdissect_options_b52 ndo52 = {0};

    /* Call both with the shared input */
    ieee802_11_if_print_b49(&ndo49, &h49, buf);
    ieee802_11_if_print_b52(&ndo52, &h52, buf);

    return 0;
}
