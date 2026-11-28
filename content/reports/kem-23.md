<!-- synchronized report: kem-23/report.md -->
Candidate: Mito
Family: Code-based
Archive: [Mito.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Mito.zip) (SHA-256: `ee11788a3e8bf8653d18ade6580c47a331b91e7eac3e31a5a6750a4b4cfb827b`)

## kem-23-1: Mito-E discards every erasure before Reed–Solomon decoding

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Mito-1-E and Mito-2-E, all three parameter sets
Discovery: Trivial
Exploitation: DFR/conformance failure; concrete decapsulation failure rate not measured
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Yan, Cao, Tong and Zhang's independent analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/767XHHZ62MOHOCT2V6HBJT43R6FTXOZV/)

The specification defines Mito-E by distance-informed errors-and-erasures decoding. The modified inner Reed–Muller decoder returns an erasure count `t` and erasure positions `pos`; the outer Reed–Solomon decoder is then supposed to use them, with correctness condition `2ν+t ≤ N−K`. The E-variant DFR calculation relies on this extra decoding capacity.

All twelve submitted Mito-E source trees (six parameter variants, each in reference and optimized form) compute `t` and `pos` but immediately discard both. They call the same two-argument, errors-only `reed_solomon_decode(m,tmp)` used by the baseline scheme. Thus the shipped E variants do not implement the algorithm whose DFR is claimed in the PDF. All twelve set `PARAM_ALPHA=7`; the specification gives 9 for Mito-1-E-128 and 11 for Mito-1-E-512. Without a fresh analysis of the shipped decoder and constants, this is not yet a quantified key-recovery attack.

### Reproducing

```sh
IDS=kem-23 ./download.sh             # if orig/kem-23/orig.zip is absent
unzip -qo orig/kem-23/orig.zip -d kem-23  # if optimized sources are absent
python3 security/design_parameter_audit.py --report-id kem-23-1
```

The `kem-23-1` check verifies this data-flow defect in all twelve E-variant
source trees retained in the public harness—six reference and six optimized
trees—and checks the corresponding errors-and-erasures requirement in the
PDF.

[Yan, Cao, Tong and Zhang's 2026-11-08 analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/767XHHZ62MOHOCT2V6HBJT43R6FTXOZV/) independently confirms the mismatch and computes conditional errors-only decoder bounds. Four of its six upper bounds (the 256- and 512-bit E sets) are weaker than their respective targets; both 128-bit sets meet their targets under those bounds. An upper bound above a target does not establish that the actual failure rate exceeds it. Their controlled correction-boundary tests report 0/96 successes for the submitted decoder and 96/96 for a corrected decoder, with neither path failing in 1,024 structured-noise frames per set. They also report that the RM decoder returns duplicate candidates for noiseless `0x00` and `0x80`, creating a zero confidence gap and false erasure marks: simply forwarding those marks fails all 96 noiseless zero-message tests. A repair therefore needs to address the duplicate-candidate behavior as well as the discarded erasure information. These controlled tests do not measure the submitted decoder's operational DFR.

```sh
rg -n 'reed_muller_decode\(tmp, pos, em\)|reed_solomon_decode\(m, tmp\)' kem-23/Implementations --glob code.c
```

## kem-23-2: Mito uses the external DRBG as an XOF

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All nine Mito reference implementations
Discovery: Trivial
Exploitation: Replacing the external RBG changes deterministic key, ciphertext and parsing expansions; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

Mito's function named `xof_init` is exactly `init_random_number(xof_ctx, seed, seed_size)`, and `xof_get_bytes` reads the external DRBG stream (`symmetric.c:50–67`). Key generation, parsing and encryption seed this wrapper from protocol values (`mito_pke.c:39–45,87`; `parsing.c:17–33`). Correct operation therefore depends on one particular RBG's deterministic stream.

The archive is self-consistent and no confidentiality break is asserted. The Low defect is using an external RBG contract where the scheme requires a specified XOF.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-23-2
```

## kem-23-3: Short ciphertexts reach Mito's fixed-offset parser

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All nine Mito parameter sets, reference and optimized decapsulation
Discovery: Trivial
Exploitation: A caller-supplied short ciphertext buffer causes an out-of-bounds read; no disclosure or key recovery is demonstrated
Credit: Hao Yan, Yuhang Cao, Yao Tong and Qiaosheng Zhang (Shanghai AI Lab; AI-assisted discovery, human verified)
Date: 2026-11-08
Original source: [Yan, Cao, Tong and Zhang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/767XHHZ62MOHOCT2V6HBJT43R6FTXOZV/)

All 18 `kem_dec` wrappers discard `ct_len_bytes` and pass only `ct` to `crypto_kem_dec` (`KEM_AlgorithmInstance.c:60–66`). Its parser copies the vectors and the 32-byte salt at fixed offsets (`parsing.c:63–69`), so a genuinely short buffer is read beyond its end before any check. With a heap copy one byte shorter than the ciphertext, passed with its true length, AddressSanitizer reports a heap-buffer-overflow read in the salt copy in all nine sets of both implementation families. Honest round trips through exact-size buffers raise no report.

The authors' analysis (§4.1.4) also describes recovering the adjacent byte with up to 256 decapsulation queries when that byte is stable and key equality is observable. That extension is not reproduced here, so no memory disclosure is claimed. Extended buffers are ignored past the fixed length; that alias alone is not a finding for a fixed-size ciphertext domain.

The wrapper should reject any `ct_len_bytes` other than `CIPHERTEXT_BYTES` before reading the ciphertext.

### Reproducing

```sh
python3 kem-23/reproduce_short_ciphertext.py
```

The script checks the original archive against the SHA-256 above, fetching it if absent, and compiles each reference and optimized tree with AddressSanitizer, this repository's unmodified API shim and a small driver in a temporary directory. For each build it requires a clean honest round trip and a heap-buffer-overflow read in `mito_c_kem_from_string` for the one-byte-short buffer. It takes about 40 seconds and exits 77 if the compiler cannot build with AddressSanitizer.

## kem-23-4: The implicit-rejection key hashes uninitialised stack bytes

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All nine Mito parameter sets; reference and optimized implementations
Discovery: Moderate
Exploitation: The rejection key for a fixed invalid ciphertext can change between calls, which reveals rejection to a party who can compare the keys; no confidentiality attack demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

Decapsulation derives the implicit-rejection key with `hash_j`. That function declares its input buffer as `in[SEED_BYTES + PARAM_K_BYTES + sizeof(ciphertext_kem_t)]`, copies in the public-key hash, `σ` and the serialized ciphertext, and then hashes `sizeof(in)` bytes (`symmetric.c:117–128`). The in-memory ciphertext structure stores its vectors in 64-bit words and is larger than the serialized ciphertext, so the last 14 to 32 bytes of the buffer are never written. They are whatever the stack held.

The rejection key is therefore not a deterministic function of the secret and the ciphertext. In our build, three of the nine reference sets (Mito-1-512, Mito-2-E-128, Mito-2-E-512) returned two different keys for the same invalid ciphertext when the stack held different residue. The valid path does not use `hash_j` and was stable. Implicit rejection relies on an invalid ciphertext always mapping to the same pseudorandom key; a party who can submit one ciphertext twice and compare the results can detect rejection when the keys differ. The stale bytes also enter the hash from earlier computations, but we did not find a way to recover them from the output. Whether the key varies in a given deployment depends on the compiler and call sequence.

### Reproducing

```sh
sh kem-23/reproduce_reject_key_stack.sh
```

The witness checks `hash_j` in all 18 trees and, for each reference set, requires the hashed buffer to be longer than the bytes written into it. It also decapsulates one invalid ciphertext twice over different stack contents and reports how many sets returned two different keys; that count is informative, since it depends on the compiler's stack layout.

## kem-23-5: A failed hash gives an all-zero encapsulated key

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: All nine Mito parameter sets, reference and optimized implementations
Discovery: Moderate
Exploitation: If one hash allocation fails, encapsulation returns success with an all-zero shared secret and all-zero encryption coins; no remote way to force the failure is shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; witness by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-16
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LEER3FLCOUBX4KTTDL73CCQPAZDYHIGI/)

`crypto_kem_enc` zero-initialises `K_theta` (`mito_kem.c:81`) and fills it with `hash_g` (`:89`), a `void` wrapper around the contest's `pseudohash` (`symmetric.c:106`). The helper returns an error without writing its output when its internal allocation fails. Encapsulation then encrypts with `theta = 0` (`:90–91`), copies the zero key into `ss` (`:94`) and returns 0 (`:96`).

In all 18 trees, failing that allocation once made encapsulation return 0 with a shared secret equal to the 64 zero bytes an attacker predicts. The receiver's decapsulation disagrees, so the exposure is limited to the encapsulator's copy of the key and anything it protects. A failure of the same hash during decapsulation leads to re-encryption mismatch and implicit rejection, and does not expose a key.

The failing allocation is a fixed-size buffer inside the contest helper. KEM input sizes are fixed, so a caller cannot choose it, and no remote way to force the failure is shown; memory pressure or a resource limit is needed. The candidate's defect is discarding the helper's status and returning success.

Reclassified from High to Medium on 2026-11-23. Anyone can exploit the faulted result from public data, but the failing allocation is a fixed-size buffer inside the contest's provisional helper, which a replacement need not have, and the attacker cannot cause the failure.

### Reproducing

```sh
sh kem-23/reproduce_zero_encaps_key.sh
```

The witness wraps `malloc` to fail exactly the allocation of the size `hash_g` requests and runs an unfaulted control for each set.

## kem-23-6: The declared hash output lengths fit neither the encapsulation algorithm nor the submitted code

Severity: Low
Status: Confirmed
Layer: Design
Affected: The written specification of Mito.KEM (§3.1.2, Algorithms 9 and 10), all nine parameter sets; the submitted implementations use different lengths and are self-consistent
Discovery: Trivial
Exploitation: An implementation written from the specification cannot derive `(K, θ)` and hashes the encapsulation key to a different length from the submitted code; no security consequence
Credit: Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, with MechCrypto assistance
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/key-encapsulation/kem-23_Mito)

Section 3.1.2 (physical p. 25) declares `H_comp : F_2^∞ → B^(2λ_seed)` and `H_gen : F_2^∞ → B^(λ_seed)`, and Table 3.1 fixes `λ_seed` at 64 bytes (physical p. 23). Algorithm 9, line 3, and Algorithm 10, line 4, set `(K, θ) ← H_gen(H_comp(ek) ‖ m ‖ salt)` (physical pp. 31–32), where Table 3.3 gives `K` and `θ` 64 bytes each (physical p. 24). One 64-byte output cannot supply both values, and the specification states no rule for splitting or extending it. Algorithm 10, line 6, takes the single 64-byte rejection key from the same `H_gen`. `H_mask`, declared on the same page for masking values, is used by no algorithm.

The submitted code uses the opposite lengths. `hash_h`, its `H_comp`, returns 64 bytes, and `hash_g`, its `H_gen`, returns 128 bytes (`symmetric.c:88–90,100–107`). Encapsulation and decapsulation take bytes 0–63 as `K` and bytes 64–127 as `θ` (`mito_kem.c:89–94,138–140`). The rejection key comes from a third function, `hash_j`, with a 64-byte output (`symmetric.c:117–129`). All 18 trees contain the same four calls.

An implementation that follows the declared lengths hashes the encapsulation key to 128 bytes, so its input to `H_gen` differs from the submitted code's, and it then has no defined way to obtain `θ`. Its keys and ciphertexts cannot match the submitted test vectors. Exchanging the two declared lengths and reading line 6 as `H_mask` reproduces the code, so the errors are editorial, but nothing in the specification states that correction. There is no security consequence.

### Reproducing

```sh
pdftotext -f 25 -l 32 -layout kem-23/kem-23-spec.pdf - | grep -n -B1 -A1 'Hgen\|Hcomp'
grep -n 'pseudohash(' kem-23/Implementations/Reference_Implementation/Mito-1-128/symmetric.c
```

This is a source witness.
