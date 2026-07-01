# Chained KLEE Harness: Bug 49 + Bug 52 (tcpdump 4.9.2, `print-802_11.c`)

## Goal

Bug 49 and bug 52 were originally two separate, independently-generated
KLEE drivers that both targeted `ieee802_11_if_print`. The goal of this
exercise was to combine them into a **single harness** so that **one
KLEE invocation, over one symbolic input space**, discovers both bugs —
rather than running two separate binaries.

## Why this wasn't a simple "call the function twice" merge

Looking at the actual `print-802_11.c` source behind each bug (not just
the driver stubs), two structural problems had to be solved first:

### 1. Symbol collisions
Both bugs' source files define the same four externally-linked
functions: `ieee802_11_if_print`, `ieee802_11_print`,
`mgmt_body_print`, and `handle_beacon`. Compiling both files into one
bitcode module and linking them produces duplicate-symbol errors.

**Fix:** each file's four public functions were renamed with a
version-specific suffix (`_b49` / `_b52`) in `spine_49.c` and
`spine_52.c`. The internal vulnerable logic (`parse_elements`, still
`static`/file-scoped in both, so no collision there) was left
byte-for-byte identical to the original — only the public entry point
names changed.

### 2. Incompatible types sharing the same names
- Bug 49 uses a custom, minimal `pcap_pkthdr { len; caplen; }` and a
  1-field placeholder `netdissect_options`.
- Bug 52 uses the real `<pcap.h>` `pcap_pkthdr` layout (`ts`, `caplen`,
  `len`) and a `netdissect_options` struct with real `ndo_*` flags.

These can't share one instance. **Fix:** each renamed spine keeps its
own local type definitions (`pcap_pkthdr_b49` vs. `pcap_pkthdr_b52`,
etc.), and the combined driver allocates a **separate** `ndo`/header
pair for each spine, exactly mirroring what each bug's original driver
did.

### 3. The real obstacle: an unconditional sink
Both spines end their `parse_elements` function with:
```c
klee_assert(0 && "SAILOR_SINK_REACHED_BXX");
```
This fires **unconditionally** — it's not gated behind any symbolic
branch, it fires the moment `parse_elements` is reached at all.
`klee_assert` terminates the current KLEE execution state on failure.

This matters because if the driver just called both entry points
back-to-back in one `main()`, the **first** call would end every
execution state right there, and the second call would never execute
on any path. You'd only ever observe one bug from that binary, never
both — no matter how long KLEE ran.

**Fix — a symbolic selector.** Instead of calling both spines
sequentially, the driver makes the *choice of which spine to call* a
function of one symbolic byte:

```c
unsigned char selector;
klee_make_symbolic(&selector, sizeof(selector), "spine_selector");

if (selector & 1) {
    // Path A: call ieee802_11_if_print_b49(...)
} else {
    // Path B: call ieee802_11_if_print_b52(...)
}
```

At that `if`, KLEE forks into two independent execution states — one
where `selector` is odd (goes to bug 49's spine) and one where it's
even (goes to bug 52's spine). Both states are explored within the
**same KLEE invocation**, over the **same underlying symbolic input**
(the 512-byte packet buffer `buf`, shared by both branches, plus the
selector byte). This is what "one input triggers both bugs in one run"
means in practice for sinks that are unconditional per-call: the
*input space* covers both bugs simultaneously, even though any single
*concrete* test case only ever exercises one branch.

## Files

| File | Purpose |
|---|---|
| `spine_49.c` | Bug 49's original `print-802_11.c` logic, entry points renamed with `_b49` suffix, internal vulnerable code unchanged. |
| `spine_52.c` | Bug 52's original `print-802_11.c` logic, entry points renamed with `_b52` suffix, internal vulnerable code unchanged. |
| `driver.c` | Combined harness: one symbolic packet buffer, one symbolic selector byte, branches to whichever spine the selector picks. |

## Build

```bash
clang-13 -I /snap/klee/18/usr/local/include -c -emit-llvm -g -O0 \
  -Xclang -disable-O0-optnone spine_49.c -o spine_49.bc

clang-13 -I /snap/klee/18/usr/local/include -c -emit-llvm -g -O0 \
  -Xclang -disable-O0-optnone spine_52.c -o spine_52.bc

clang-13 -I /snap/klee/18/usr/local/include -c -emit-llvm -g -O0 \
  -Xclang -disable-O0-optnone driver.c -o driver.bc

/usr/lib/llvm-13/bin/llvm-link spine_49.bc spine_52.bc driver.bc -o combined.bc
```

## Run

```bash
klee --libc=uclibc --posix-runtime --max-time=600 combined.bc
```

## Result

A single `klee` invocation on `combined.bc` produced **two distinct
error reports** in the same run:

```
KLEE: ERROR: spine_49.c:74: ASSERTION FAIL: 0 && "SAILOR_SINK_REACHED_B49"
KLEE: NOTE: now ignoring this error at this location
KLEE: ERROR: spine_52.c:59: memory error: out of bound pointer
KLEE: NOTE: now ignoring this error at this location
```

- **Bug 49** was confirmed via its synthetic sink marker
  (`SAILOR_SINK_REACHED_B49`) — the `selector`-odd path reached
  `parse_elements_b49` and hit the unconditional assertion, as
  designed.
- **Bug 52** was confirmed even more strongly than expected: instead
  of just reaching its own sink marker, KLEE's memory-safety checker
  caught a genuine **out-of-bounds pointer read** inside
  `parse_elements_b52` (around the `case 5:` / `memcpy` handling of
  the TIM element) before execution ever got to the assert. This is
  the real underlying vulnerability, not just a "line reached" marker.

Each error corresponds to a separate `.err` file under
`klee-out-0/`, each paired with a `.ktest` file holding the concrete
`buf` bytes and `selector` value KLEE solved for to steer down that
branch. Inspect with:

```bash
ls klee-out-0/*.err
ktest-tool klee-out-0/testNNNNNN.ktest
```

to see the exact selector value (odd vs. even) that produced each
crash — direct evidence that one shared symbolic input space, explored
in one run, is sufficient to surface both bugs.

## Takeaway / reusable pattern

For chaining two bug drivers that target the same or related
functions:

1. **Check for symbol/type collisions first** if both bugs' source
   ships its own copy of the vulnerable spine — rename externally
   linked functions per-bug before linking.
2. **Check whether each bug's sink is conditional or unconditional.**
   If unconditional (fires as soon as the function is reached,
   independent of input), sequential calls in one `main()` will only
   ever surface the first one — a state-terminating sink cuts off
   everything after it on every path.
3. For unconditional sinks, **make the branch selection itself
   symbolic** (a selector byte, or reuse a semantically-unused input
   byte) so KLEE forks into separate states for each bug, all
   discoverable from a single invocation.
4. For truly data-dependent sinks (bugs that only fire on specific
   buffer contents), sequential calls in one `main()` work fine as
   long as the first call doesn't abort/terminate the process on
   the paths you care about for the second call.










<img width="1259" height="573" alt="image" src="https://github.com/user-attachments/assets/7f465f2c-d88d-4a1e-a51e-97cb3346cb26" />
