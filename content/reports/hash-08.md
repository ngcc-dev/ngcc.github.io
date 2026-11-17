<!-- synchronized report: hash-08/report.md -->
Candidate: Duet
Family: Symmetric (dual-branch sponge with capacity feed-forward)
Archive: [Duet.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Duet.zip) (SHA-256: `989978bcefbe20124943b2003908226c48e0f05b5ec8db510e7cdb89c2299f1e`)

## hash-08-1: Duet-768 reference reads one word past a stack array

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Duet-768 reference implementation
Discovery: Trivial
Exploitation: Out-of-bounds stack read of 8 bytes on every absorbed block; the value is unused and the digest is unaffected
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

`sigma_permutation` copies the block into locals and reads `block[17]` (`CryptHash_Duet-768.c:288`), but its argument is the 17-word array `SigmaMi[WORDS_r]` (`:377,385`), whose last valid index is 16. The value `w17` is never used. An unoptimized build under AddressSanitizer stops with a stack-buffer-overflow read of size 8 at that line for any message; UndefinedBehaviorSanitizer reports it at `-O1` and `-O2`, where the dead load is otherwise removed. The digest and the known-answer tests are unaffected.

### Reproducing

```sh
sh hash-08/reproduce_sigma_oob.sh
```

## hash-08-2: Output beyond the digest length does not follow the specified XOF

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Duet-512, -768 and -1024; reference, AVX2, AVX-512 and NEON implementations
Discovery: Moderate
Exploitation: A request for more than h bits returns output that differs from the specified function from bit h onward and includes capacity bits the specification keeps hidden; fixed-length digests are unaffected
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

The specification's extendable output squeezes h bits per step (§2.1, §2.5 and Algorithm 1, pp. 3–7). `CryptHash` accepts any `digest_len_bits` from 1 to 8192 (`CryptHash_Duet-512.c:397`), but its squeeze step copies up to c bits of the capacity per step (`:372`; `-768.c:407`, `-1024.c:396`; the optimized trees do the same). The capacity is 64 bits wider than the digest for Duet-512 and Duet-768 and 128 bits wider for Duet-1024.

Against an independent model written from the specification, all 129 tested outputs of at most h bits match. Outputs longer than h bits differ from bit h onward, and bits h to c−1 equal the capacity tail that the specified squeeze does not output. All such outputs match a model that squeezes c bits per step instead.

The submission's `README.md` says `digest_len_bits` must equal the digest length, no known-answer test covers longer outputs, and the call does not require an XOF. The defect is that the code accepts longer requests and returns something other than the specified function. Its effect on the claimed properties is unresolved: releasing the capacity tail lowers the hidden state during squeezing from r + c − h to r bits.

### Reproducing

```sh
sh hash-08/reproduce_xof_rate.sh
```

The witness compares reference and AVX2 builds of all three instances with a Python model of Algorithm 1. It needs Python 3.
