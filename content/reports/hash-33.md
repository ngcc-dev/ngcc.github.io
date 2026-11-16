<!-- synchronized report: hash-33/report.md -->
Candidate: Thunder Hash Family
Family: Symmetric (feed-forward sponge)
Archive: [Thunder.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Thunder.zip) (SHA-256: `db6970d54250084ea73cc1a47bd56c868e5e478cdfa3746ff7b69d30c690b0c8`)

## hash-33-1: Clang compiles the XOF output copy to a branch on each output bit

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference Thunder-XOF-256, -384 and -512, x86 and ARM trees, when built with Clang; GCC builds inspected so far are not affected
Discovery: Trivial
Exploitation: Side-channel dependent; no timing extraction demonstrated
Credit: aimir (GitHub @aimir)
Date: 2026-11-16
Original source: [GitHub issue #40](https://github.com/ngcc-dev/ngcc-harness/issues/40)

The XOF copies each squeezed block into the output bit by bit with `copy_bits_msb`, which writes each bit with `if (src_bit) dst |= mask; else dst &= ~mask;` (`CryptHash_AlgorithmInstance.c:187`). The control flow therefore follows the value of every output bit, and XOF output is secret whenever it is used as key material.

GCC 15 at `-O2` turns the conditional into `cmov` on x86-64. Ubuntu Clang 21.1.8 at `-O2` does not: in the full x86 Thunder-XOF-256 and -512 and ARM Thunder-XOF-384 translation units compiled for x86-64 it keeps a `bt` on the output bit followed by `jae` inside the inlined copy loop, and the same helper compiled for AArch64 keeps a `tbz` on that bit. The issue reports the branch for Apple Clang 17 on ARM64 at `-O2` and `-Os` for all three sets, and on x86-64 for Thunder-XOF-256. All twelve archived copies of the helper, including the self-assessment trees, have the same source line.

Each output bit therefore selects one of two short instruction paths. A local branch-predictor or instruction-trace observer could learn the bits; no timing extraction was attempted.

Constant-time fix (easy, hence Low): insert the bit arithmetically, for example `dst[i] = (dst[i] & ~mask) | (mask & -src_bit)`, or copy whole bytes when the offset is byte-aligned.

### Reproducing

Compile `Thunder-X86/Implementations/Reference_Implementation/Thunder-XOF-256/CryptHash_AlgorithmInstance.c` with `clang -O2 -S` for x86-64 and search the copy loop for `bt` followed by `jae`; with `gcc -O2 -S` the same loop has `cmov`. The issue's attachment gives the Apple Clang matrix and a branch-free patch.
