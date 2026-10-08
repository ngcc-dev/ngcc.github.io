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
Follow-up source: [QCTM team's 2026-10-08 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/S4LPBREM3EYTVIOGUDFFMHIM2UCD2VXG/)

When the `LOCALLY_QUASI_CYCLIC_TWISTED_MCELIECE_TRACE_DEC` environment variable is present, encapsulation copies the fixed-weight secret error positions into file-static process-global storage. The same opt-in trace path prints decoder stages, syndrome-difference counts, decoded weight, and failure-location diagnostics to standard error.

The logic is present in the compiled QCTM128, QCTM256, and QCTM512 reference sources. The retained error positions are secret per-encapsulation material and should be erased after ciphertext construction, not persisted for a later decoder trace.

The static buffer has no exported accessor, so merely setting the environment variable does not reveal its contents to a remote KEM caller. Exploitation additionally requires stderr visibility, local/in-process memory access, or another disclosure primitive. This is a confirmed implementation-security and secret-lifetime defect, not a demonstrated remote key-recovery attack.

### Proposed fixes

In its 2026-10-08 response, the QCTM team says it removed the global error-position storage and trace diagnostics and added clearing of temporary error buffers in both implementation trees. This records the team's revision without evaluating it.

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
Follow-up source: [QCTM team's 2026-10-08 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/S4LPBREM3EYTVIOGUDFFMHIM2UCD2VXG/)

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

### Proposed fixes

In its 2026-10-08 response, the team reports increasing QCTM128's code length from 10,070 to 10,545 and QCTM256's from 19,000 to 19,551. It gives revised DS-DOOM estimates of 2^136.294 and 2^264.170 bit operations under the stated multi-instance model; QCTM512's length remains 38,000. The revised sets require new keys and test vectors. These proposals are recorded without evaluating them.

### Reproducing

Install `numpy` and `scipy`, then run:

```sh
python3 kem-32/reproduce_multi_instance.py
```

The witness downloads the official estimator at commit `39b78dcc077793cfa3ccdce8d032ece76825ca55`, verifies both its archive and `doom.py` hashes, reproduces each crossing and its preceding above-target point, and checks the 512-bit control.

## kem-32-3: The bundled RNG limits QCTM-512 key-generation randomness to 384 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: QCTM512 reference and optimized builds using the bundled `rng.c`, including the KAT-labelled API adapter; a caller-supplied replacement RNG is not assessed
Discovery: Trivial
Exploitation: At most 2^384 bridge-seed trials, about 2^424 cycles using the measured key-generation cost, then decapsulation
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

The submitted QCTM512 builds link a bundled AES256-CTR-DRBG (`Reference_Implementation/QCTM512/Makefile:33–42,54–63`). Its entire state is a 32-byte `Key` and 16-byte `V` (`rng.h:19–23`, `rng.c:113–129`). The KAT program seeds it with 48 bytes. The only supplied path that seeds it from the external RBG is an adapter labelled `api-pkc-kat`, which likewise draws 48 bytes before every `kem_keygen` (`KEM_AlgorithmInstance.c:18–27,70–86`, also in the optimized tree). The local generator supplies the 64-byte seed to deterministic key generation (`kem.c:557–592`, `seeded_keygen.c:797–848`).

An attacker can enumerate the 2^384 possible bundled-RNG states, reproduce each candidate public key, and retain its decapsulation key on a match. The published x86_1 benchmark measures QCTM512 key generation at about 793.78 billion cycles (2^39.5); using that as an indicative per-trial cost gives about 2^424 cycles total, below the 512-bit target (§3.1 and §3.2.3, physical pp. 5–6). This does not rely on predicting or resetting the external RBG: replacing it by an ideal source still leaves the 48-byte local state. The bound is theoretical; no exhaustive search was run, and it does not describe a build that replaces the bundled RNG.

### Reproducing

```sh
python3 kem-32/reproduce_bridge_seed_ceiling.py
```

The certificate checks the submitted build flags, bundled RNG state, and bridge-to-keygen-seed source path. It is a source-and-counting argument, not a full-size key recovery.

## kem-32-4: Folding exposes an ordinary Goppa quotient of the public code

Severity: Medium
Status: Confirmed
Layer: Design
Affected: QCTM128, QCTM256, and QCTM512 in the submitted specification and reference and optimized public-key constructions
Discovery: Non-trivial
Exploitation: An order-19 public quotient reduces to an ordinary Goppa code after one puncture; recovery of a full QCTM decapsulation key is not demonstrated
Credit: Liping Wang; independent quotient audit by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-08
Original source: [Liping Wang's QCTM structural-analysis post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XGAGQXXF4DD735AOVZJY67QHJS2M6LBH/)

Additional reference: [Weis, *Improving GIJS Key Recovery for Classic McEliece*, ePrint 2026/1984](https://eprint.iacr.org/2026/1984)

The specification argues that the twisted construction prevents a direct folding attack (§6.3, physical pp. 19–20). In the submitted public-key construction, however, the twist is confined to the omitted final field row: the published matrix uses the first `t−1` ordinary syndrome rows plus an all-ones parity row (reference QCTM128 `goppa.c:1889–1893,2050–2127`; `decode.c:103–139`; the other trees use the same construction). The support consists of 19-element orbits (`seeded_keygen.c:610–691`). Folding the public matrix across each orbit therefore exposes an ordinary degree-`t/19` Goppa check space with one parity row. Puncturing one coordinate gives an ordinary binary Goppa code.

The exact public and secret-oracle row spaces agree on the archived KAT keys for all three sets:

| Set | Public quotient | Punctured Goppa code |
|---|---:|---:|
| QCTM128 | `[530,259]` | `[529,259]` |
| QCTM256 | `[1000,513]` | `[999,513]` |
| QCTM512 | `[2000,1045]` | `[1999,1045]` |

This defeats the stated rationale for excluding ordinary-Goppa structural analysis, hence Medium. The forum post estimates quotient key recovery using Weis's heuristic GIJS model, but does not show how a recovered quotient key yields a key for the full twisted QCTM decapsulation or cost that lifting step. No full-scheme key recovery is claimed here.

### Reproducing

```sh
sh kem-32/reproduce_folded_quotient.sh
```

The wrapper downloads the SHA-256-pinned submitted archive and checks the public quotient against the secret Goppa description for KAT record 0 of each set. The private key is used only as an independent oracle for the row-space comparison; the quotient is derived from the public key alone. The witness does not recover a decapsulation key.

## kem-32-5: Reported structural key recovery for QCTM256 and QCTM512

Severity: Critical
Status: Lead
Layer: Design
Affected: QCTM256 and QCTM512, conditional on lifting the quotient attack to the full KEM
Discovery: Hard
Exploitation: The reporter estimates 2^141.3 and 2^142.0 bit operations respectively; full QCTM key recovery has not been demonstrated
Credit: Liping Wang
Date: 2026-10-08
Original source: [Liping Wang's QCTM structural-analysis post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XGAGQXXF4DD735AOVZJY67QHJS2M6LBH/)

Additional reference: [Weis, *Improving GIJS Key Recovery for Classic McEliece*, ePrint 2026/1984](https://eprint.iacr.org/2026/1984)

The public QCTM code exposes an ordinary Goppa quotient of degree 27 or 53 for these sets. The reporter applies Weis's heuristic GIJS key-recovery model to that quotient, estimating the costs above (or 2^176.7 and 2^177.7 bit operations with square-root memory charging). If this yields full QCTM decapsulation keys at comparable cost, both estimates fall below the claimed 256- and 512-bit levels.

Three steps remain open: the GIJS/Weis assumptions have not been established at these quotient degrees; quotient-key recovery has not been demonstrated on a QCTM key; and lifting a recovered quotient key through the order-19 alignment and twist gauge to a full decapsulation key has not been implemented or costed. This is a candidate-specific Critical *lead*, not a confirmed key-recovery attack. The archived-key audit in `kem-32/reproduce_folded_quotient.sh` confirms only the prerequisite quotient.
