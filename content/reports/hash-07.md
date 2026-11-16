<!-- synchronized report: hash-07/report.md -->
Candidate: Dragon Hash Family
Family: Symmetric (feed-forward sponge, ARX permutation)
Archive: [Dragon.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Dragon.zip) (SHA-256: `088759817e3193e0ca02c3a3669fd05ac70e833b0447f336666268b61846b26c`)

## hash-07-1: Clang compiles the XOF output copy to a branch on each output bit

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference Dragon-XOF-256, -384 and -512, x86 and ARM trees, when built with Clang; GCC builds inspected so far are not affected
Discovery: Trivial
Exploitation: Side-channel dependent; no timing extraction demonstrated
Credit: aimir (GitHub @aimir)
Date: 2026-11-16
Original source: [GitHub issue #40](https://github.com/ngcc-dev/ngcc-harness/issues/40)

The XOF squeezes each block into a buffer and copies it bit by bit into the output with `copy_bits_msb` (`CryptHash_AlgorithmInstance.c:94–107`, called at `:228`). The helper writes each bit with `if (src_bit) dst |= mask; else dst &= ~mask;` (`:101`), so the control flow follows the value of every output bit. The specification lists key derivation among the family's uses, where the XOF output is secret.

GCC 15 at `-O2` turns the conditional into `cmov` on x86-64. Ubuntu Clang 21.1.8 at `-O2` does not: in the full x86 Dragon-XOF-256 and -512 translation units it keeps a `bt` on the output bit followed by `jae` inside the inlined copy loop, and the same helper compiled for AArch64 keeps a `tbz` on that bit. The issue reports the same behaviour for Apple Clang 17 on ARM64 and x86-64 at `-O0`, `-O2` and `-Os`. All twelve archived copies of the helper, including the self-assessment trees, have the same source line.

Each output bit therefore selects one of two short instruction paths. A local branch-predictor or instruction-trace observer could learn the bits; no timing extraction was attempted.

Constant-time fix (easy, hence Low): insert the bit arithmetically, for example `dst[i] = (dst[i] & ~mask) | (mask & -src_bit)`, or copy whole bytes when the offset is byte-aligned.

### Reproducing

Compile `Dragon-x86/Implementations/Reference_Implementation/Dragon-XOF-256/CryptHash_AlgorithmInstance.c` with `clang -O2 -S` for x86-64 and search the copy loop for `bt` followed by `jae`; with `gcc -O2 -S` the same loop has `cmov`. The issue's attachment gives the Apple Clang matrix and a branch-free patch.
