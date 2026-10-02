<!-- synchronized report: kem-32/report.md -->
Candidate: QCTM
Family: Code-based (quasi-cyclic twisted McEliece)
Archive: [QCTM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QCTM.zip) (SHA-256: `24a3986a4fbb852a677267a6443756328eae3642af770e767fe38f8291f294db`)

## kem-32-1: Debug path retains the secret error vector

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets when tracing is enabled
Discovery: Trivial
Exploitation: Requires stderr visibility or local/in-process memory access
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

When the `LOCALLY_QUASI_CYCLIC_TWISTED_MCELIECE_TRACE_DEC` environment variable is present, encapsulation copies the fixed-weight secret error positions into file-static process-global storage. The same opt-in trace path prints decoder stages, syndrome-difference counts, decoded weight, and failure-location diagnostics to standard error.

The logic is present in the compiled QCTM128, QCTM256, and QCTM512 reference sources. The retained error positions are secret per-encapsulation material and should be erased after ciphertext construction, not persisted for a later decoder trace.

The static buffer has no exported accessor, so merely setting the environment variable does not reveal its contents to a remote KEM caller. Exploitation additionally requires stderr visibility, local/in-process memory access, or another disclosure primitive. This is a confirmed implementation-security and secret-lifetime defect, not a demonstrated remote key-recovery attack.

### Reproducing

This is a source-level secret-lifetime check, not a remote exploit. Fetch the
official archive, then inspect the QCTM128 reference `kem.c` at lines 15–20
(file-static buffer), 523–531 (trace use), and 641–645 (copy from the fresh
encapsulation error). The QCTM256 and QCTM512 reference files have the same
pattern.

```sh
IDS=kem-32 ./download.sh
./extract.sh kem-32
rg -n 'debug_last_error|TRACE_DEC' kem-32/Implementations/Reference_Implementation/QCTM*/kem.c
```

## kem-32-2: Same-key multi-instance decoding misses QCTM-128 and -256 targets

Severity: Critical
Status: Confirmed
Layer: Design
Affected: QCTM128 and QCTM256
Discovery: Moderate
Exploitation: About 2^127.66 work after 2^79 ciphertexts, or 2^255.34 work after 2^76 ciphertexts
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-30

Additional reference: [May and Sá Diogo, *Multi-Instance Security Degradation of Code-Based KEMs*, ePrint 2026/517, pinned 2026-06-12 version](https://eprint.iacr.org/archive/2026/517/20260612:161211)

QCTM encapsulation publishes `C=H e^T` for a fresh weight-`w` error under a reusable public key. The order-19 circulant part gives 19 public rotated targets for every observed ciphertext. Omitting the two non-circulant tail checks while searching gives effective dimensions 4,958, 9,784 and 19,892; the fixed-weight parity restores the remaining check. A candidate rotation is unshifted and verified against the complete public syndrome, after which `K=H(1,e,C)` is public.

May and Sá Diogo's pinned DS-DOOM estimator gives:

| set | observed ciphertexts | log2(bit operations) | log2(memory bits) | target |
|---|---:|---:|---:|---:|
| QCTM128 | 2^79 | 127.661 | 95.592 | 128 |
| QCTM256 | 2^76 | 255.336 | 96.271 | 256 |
| QCTM512 (control) | 2^80 | 524.342 | 124.253 | 512 |

The attacks are passive, use fewer than 2^80 observed encapsulations, and need no decapsulation queries. The specification describes cached public-key state for encapsulation and reuse of decoded secret-key state across calls (§7.4), and states no per-key session cap. A hypothetical 2^64-ciphertext limit would avoid the crossings, but neither the NGCC call nor QCTM imposes one. The 128- and 256-bit claims are therefore missed and the finding is Critical.

The margins are narrow: 0.339 and 0.664 bits under this single heuristic DS-DOOM cost model, with memory estimates of 2^95.592 and 2^96.271 bits. Reducing the allowed observation exponent by one removes both reported crossings. The classification applies the policy's strict below-target rule to the cited model; it should be revisited if a better-supported cost model moves either estimate above its target.

### Reproducing

Install `numpy` and `scipy`, then run:

```sh
python3 kem-32/reproduce_multi_instance.py
```

The witness downloads the official estimator at commit `39b78dcc077793cfa3ccdce8d032ece76825ca55`, verifies both its archive and `doom.py` hashes, reproduces each crossing and its preceding above-target point, and checks the 512-bit control.
