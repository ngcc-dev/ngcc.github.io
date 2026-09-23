<!-- synchronized report: kem-17/report.md -->
Candidate: HEP-QC
Family: Code-based (quasi-cyclic)
Archive: [HEP-QC.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/HEP-QC.zip) (SHA-256: `3780991127f49b6397b4182d32b35ab7a6359bf825a707e90df0f809beeb3790`)

## kem-17-1: Publicly reproducible secret keys

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Key generation draws from a file-scope SHAKE-256 PRNG context that is never initialized by the KEM wrapper. The API-provided seeded DRNG is declared but never consumed. Each fresh process therefore begins from the same zero-initialized state and generates the same key pair.

Fresh-process tests with different API seeds produced identical public and secret keys for `hep-qc-1`, `hep-qc-3`, `hep-qc-5`, and `hep-qc-7`.

An attacker recovers a victim's secret key by starting a fresh process and invoking the submitted key-generation API once. No code-based cryptanalysis is required. The resulting secret key decapsulates the victim's ciphertexts, completely breaking the claimed KEM confidentiality.

The wrapper must initialize its PRNG from the supplied DRNG for every independent key-generation operation and must not rely on zero-initialized global state.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-17
tools/ngcc_attack keygen-fresh kem-17/lib/libhep-qc-1.so 0x01   # repeat with a different seed
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## kem-17-2: HEP-QC-7 has at most 256 bits of key-generation support

Severity: Critical
Status: Confirmed
Layer: Design
Affected: HEP-QC-7 specification
Discovery: Trivial
Exploitation: Approximately 2^256 key-generation trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

This is independent of the implementation defect above. The HEP-QC-7 specification claims 512-bit classical security, but fixes `seedKEM`, every derived seed, and the shared key `K` at 32 bytes. `KEM.KeyGen` samples one 256-bit `seedKEM` and deterministically derives `seedPKE` and the complete PKE key pair from it.

There are consequently at most `2^256` HEP-QC-7 public keys. A generic attacker can enumerate `seedKEM`, regenerate the encapsulation key, and compare it with the target public key. A match supplies the corresponding decapsulation key. The 32-byte KEM output also has at most 256 bits of delivered-key capacity.

This is a specification-level parameter-selection break of the advertised 512-bit classical level. It is not made less valid by the submitted wrapper's much cheaper predictable-key failure; repairing the wrapper still leaves this `2^256` design ceiling.

### Reproducing

Specification evidence is on physical PDF pages 12–14. Run:

```sh
python3 security/design_parameter_audit.py
```

## kem-17-3: First encapsulation in each process is publicly reproducible

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Trivial
Exploitation: Trivial for the first encapsulation in a fresh process
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

`kem_enc` draws both its message `m` and salt consecutively from the same file-scope SHAKE-256 PRNG context described in `kem-17-1`. The wrapper never initializes that context from the API-provided DRNG, so it begins in the same zero-initialized state in every fresh process.

For a fixed public key, the first encapsulation in each fresh process consequently repeats both the ciphertext and shared secret. An attacker can run the public encapsulation algorithm in a fresh process with the recipient's public key and recover the exact first session key produced by another fresh process. Fixing key generation alone does not repair this independent KEM confidentiality failure.

Every encapsulation operation must obtain fresh entropy from the API DRNG or initialize a per-operation generator from it. Message and salt generation must not use predictable global state.

### Reproducing

In all four parameter sets, `kem_enc` calls `prng_get_bytes(m, ...)` and then `prng_get_bytes(salt, ...)`; the wrapper declares the initialized API DRNG but never uses it. The permanent witness compares fresh processes with different API seeds:

```sh
tools/reproduce.sh kem-17
```

It reports identical first public-key, ciphertext, and shared-secret digests for HEP-QC. The Aigis-Enc+ control differs across the two seeds.

## kem-17-4: Public column multiplicities break the EPC-P assumption

Severity: High
Status: Confirmed
Layer: Design
Affected: All four HEP-QC parameter sets
Discovery: Moderate
Exploitation: Linear-time distinguishing; claimed structure recovery takes seconds to minutes
Credit: Tianyuan Xie
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XQ3A3A3IGNRQDLEQ6BD73ENALBGSDEO6/)

HEP-QC repeats every column of its inner Reed–Muller generator `MULT = n2/128` times before applying row mixing and a column permutation. Those operations preserve equality. The public matrix `G'` therefore has exactly `n1*128` column classes of multiplicity `MULT` and 64 singleton columns, whereas a uniform matrix has no repeated columns except with negligible probability. This gives a public, linear-time distinguisher with advantage essentially one and directly falsifies the EPC-P assumption used by the specification's first security bound.

Tianyuan Xie's [mailing-list analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XQ3A3A3IGNRQDLEQ6BD73ENALBGSDEO6/) additionally reports recovery of the affine blocks and exact secret transformation `T` on 35/35 official keys. The remaining frame-label searches are estimated at `2^84.1`, `2^131.0`, and `2^198.7` for HEP-QC-1, -3, and -5, below their 128-, 192-, and 256-bit claims. The public attachment reproduces the distinguisher, but not the full transformation recovery, so those residual key-recovery costs are less independently reproducible than the confirmed EPC-P break.

Xie also identifies an independent gap in Theorem 6.3.1's EPC-P-only IND-CPA bound: replacing `G'` by a uniform matrix in Game 2 does not make the challenge ciphertext independent of the selected message. For fixed public `s`, the noise `s*r2 + e` has at most `binomial(n,omega_r)*binomial(n,omega_e)` possible values before truncation. Its translates by two messages' codewords are therefore almost surely disjoint for a uniform `G'` (their expected overlap is bounded by the square of that support size divided by `2^(n1*n2)`). Thus the claimed *statistical* independence is false. This finite-support argument does not give an efficient ciphertext distinguisher; a computational assumption about the noise distribution is still needed. It is a proof gap, not a separate demonstrated KEM break.

### Reproducing

```sh
make -C kem-17 lib/libhep-qc-1.so
python3 kem-17/reproduce_epcp_fingerprint.py
```

On a freshly generated official HEP-QC-1 key, this prints `3^5888 + 1^64`; its uniform-matrix control prints `1^17728`.
