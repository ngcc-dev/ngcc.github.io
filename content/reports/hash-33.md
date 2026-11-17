<!-- synchronized report: hash-33/report.md -->
Candidate: Thunder Hash Family
Family: Symmetric (feed-forward sponge)
Archive: [Thunder.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Thunder.zip) (SHA-256: `db6970d54250084ea73cc1a47bd56c868e5e478cdfa3746ff7b69d30c690b0c8`)

## hash-33-1: The reference XOF implementation branches on each output bit, with a measurable timing dependence

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference Thunder-XOF-256, -384 and -512, x86 and ARM trees, when built with Clang, or with GCC without optimization; GCC at `-O2` is not affected
Discovery: Trivial
Exploitation: Running time depends on the Hamming weight of the secret output, measured locally; an observer of branch directions sees each output bit; no output recovery demonstrated
Credit: aimir (GitHub @aimir); timing measurement by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-16
Original source: [GitHub issue #40](https://github.com/ngcc-dev/ngcc-harness/issues/40)

The XOF copies each squeezed block into the output bit by bit with `copy_bits_msb`, which writes each bit with `if (src_bit) dst |= mask; else dst &= ~mask;` (`CryptHash_AlgorithmInstance.c:187`). The control flow therefore follows the value of every output bit, and XOF output is secret whenever it is used as key material.

GCC 15 at `-O2` turns the conditional into `cmov` on x86-64, but keeps the branch at `-O0`. Ubuntu Clang 21.1.8 keeps it at `-O0` and at `-O2`: in the full x86 Thunder-XOF-256 and -512 and ARM Thunder-XOF-384 translation units compiled for x86-64 it leaves a `bt` on the output bit followed by `jae` inside the inlined copy loop, and the same helper compiled for AArch64 has a `tbz` on that bit. The issue reports the branch for Apple Clang 17 on ARM64 at `-O2` and `-Os` for all three sets, and on x86-64 for Thunder-XOF-256. All twelve archived copies of the helper, including the self-assessment trees, have the same source line. With the message marked as undefined under Valgrind's memcheck, this is the only secret-dependent branch reported in any tree; the fixed-output reference and optimized builds are clean with both compilers.

The channel is measurable. On reference Thunder-XOF-256 with one 1280-bit output block:

- With GCC `-O0` the two paths differ by two instructions, and the instruction count of a call is exactly a constant minus twice the output's Hamming weight.
- Over 300,000 random messages, the running time fell by 0.22 cycles per output 1-bit with GCC `-O0` (a correlation 18.5 standard deviations from zero) and by 0.24 cycles with Clang `-O2` (24.8), where the instruction count is constant. GCC `-O2` showed no dependence (0.0).

The timing figures vary with the host and the code layout. They expose the Hamming weight of each output block, not individual bits; an observer of branch directions would see the bits themselves. No output was recovered.

Constant-time fix (easy): insert the bit arithmetically, for example `dst[i] = (dst[i] & ~mask) | (mask & -src_bit)`, or copy whole bytes when the offset is byte-aligned. The repair is local; the rating is Medium because the channel is measured.

### Reproducing

```sh
sh hash-33/reproduce_xof_output_timing.sh
```

The witness requires the taint result and the exact instruction-count relation, and prints the timing regression for each build as information. It needs Valgrind. The issue's attachment gives the Apple Clang matrix and a branch-free patch.

## hash-33-2: Fixed-output wrappers ignore the requested digest length

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Thunder-512, -768 and -1024; reference, optimized and additional implementations
Discovery: Trivial
Exploitation: A caller that sizes the output buffer from a shorter requested length receives a write beyond it; no secret disclosure or cryptographic break shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

`CryptHash` takes `digest_len_bits`, but the fixed-output implementations never read it. They return 0 and always write the instance's full 64-, 96- or 128-byte digest. A request for 256 bits from Thunder-512, with a 32-byte buffer, is therefore written 64 bytes. The three XOF instances honour the requested length, so the behaviour differs within the same submission.

The witness builds the 17 fixed-output trees that compile and calls each with requests for 256 bits and for 8 bits, in a large sentinel-filled buffer. Every call returns 0, writes the full digest, and the bytes equal those of a full-length request. The eighteenth, the X86 `Additional_Implementation/Thunder-1024` directory, does not compile as shipped, because its header and source both define `IV`. The XOF builds write exactly the 32 requested bytes.

Fix: return an error unless `digest_len_bits` equals `DIGEST_BIT_LENGTH`.

### Reproducing

```sh
sh hash-33/reproduce_digest_length.sh
```

The driver never writes out of bounds itself; it measures the write extent inside a larger buffer.
