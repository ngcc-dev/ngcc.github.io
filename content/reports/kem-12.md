<!-- synchronized report: kem-12/report.md -->
Candidate: CTL
Family: Lattice-based
Archive: [CTL.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CTL.zip) (SHA-256: `512caaf5fa04ea5ab51fb5eeee9e81f8c7c7c430b60727130067634bfb674d01`)

## kem-12-1: The specified CTL-512 public-key space has at most 256 bits of support

Severity: Critical
Status: Confirmed
Layer: Design
Affected: CTL-512 specification and reference implementation
Discovery: Trivial
Exploitation: Approximately 2^256 key-generation trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [CTL submitters' 2026-09-23 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/)

CTL-512 claims 512-bit security, but its normative short private-key format stores one 32-byte key-generation seed. The specification requires `f` and `g` to be regenerated deterministically from this seed and recomputes the public key as `h = f^-1 g mod q`.

Consequently, at most `2^256` public keys can be generated. An attacker can enumerate the seeds, recompute `h`, and compare it with the target public key; a match recovers the target trapdoor data. This ceiling is independent of the nominal lattice dimensions and is present in both the specification and submitted code.

### Proposed fixes

The [CTL submitters' response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/) proposes a 64-byte CTL-512 key-generation seed, an expansion mechanism intended to preserve the target level, corresponding private-key and deterministic-regeneration changes, and a review of the complete entropy path. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-12-1
```

The `kem-12-1` check verifies the short-key algorithms on physical PDF pages
24 and 28–36 and the corresponding reference constants.

## kem-12-2: CTL-512 returns only 384 shared-secret bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: CTL-512 reference adapter; the specification assigns a 64-byte output
Discovery: Trivial
Exploitation: The 384-bit output is 128 bits short of the required 512-bit encapsulated key; the key is also recoverable from (pk, ct) by enumerating the 48-byte message m (2^384, not run)
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [CTL submitters' 2026-09-23 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/)

The CTL-512 adapter returns a 48-byte shared secret and instantiates the ciphertext hash component `c2` at 48 bytes. The specification assigns 64 bytes to CTL-512 `c2`.

The returned key therefore has at most 384 bits of delivered-key capacity and the ciphertext format contradicts the PDF. The NGCC [Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf) §2(2) require the encapsulated key to be at least as long as the corresponding classical security level. CTL-512 misses that explicit 512-bit target and is therefore Critical, even though this dimensional shortfall is not a separate IND-CCA attack. The CTL submitters acknowledge both findings; these reports remain scoped to the archived submission.

Extended on 2026-10-17: the encapsulation randomness is also only 384 bits, so lengthening the output alone would not reach the target. `kem_enc` draws a 48-byte seed (`KEM_AlgorithmInstance.c:68,84`), and `CTL_MK(3329, 2048, 48, ...)` sets `LVLBYTES = 48` (`ctl.h:249`). In `encapsulate_explicit_seed`, the seed is the message m. The code derives s from m (`api.c:677`), forms c1 from s and pk, and sets c2 = Hash_m(s) ⊕ m. It then derives the key from m alone (`api.c:708`). The rare retry path replaces m with H(m) (`api.c:691`), which is still a function of the seed. Given only (pk, ct), an attacker can enumerate the 2^384 values of m, re-encrypt each one, and match it against ct. This recovers the key without decapsulation queries, below the 512-bit target. The reference and optimized trees have the same lines. This extension was checked by source only. The enumeration was not run.

### Proposed fixes

For CTL-512's shared secret and `c2`, the [submitters' response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/) proposes revising the length handling, key derivation, implementation, specification, documentation, test vectors, and validation. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-12-2
```

The `kem-12-2` check verifies the CTL-512 output table and the corresponding
reference constants.

## kem-12-3: Reference CTL-512 multiplication branches on every bit of the encapsulation secret

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: CTL-512 (CTL-3329-2048) reference implementation; the optimized tree multiplies by NTT and is flat. Key generation in both trees
Discovery: Trivial
Exploitation: Secret-dependent instruction count and branch trace in encapsulation and in decapsulation's re-encryption; no shared-secret or key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

CTL encrypts by computing `c1 = round(h·s / k)` for a binary polynomial `s` derived from the message. The reference CTL-512 code does this with a schoolbook product whose inner loop skips zero coefficients of `s`: `if (b[j] == 0) continue;` (`kem3329.c:145`, called from `ctl_encrypt_3329` at `:452`). Encapsulation reaches it with the fresh `s` (`api.c:690`), and decapsulation reaches it with the decrypted `s` during re-encryption, before the comparison (`api.c:764`).

One call executes 25.5 million instructions for an all-zero `s`, 35.5 million at weight 1024 and 44.4 million at weight 2048. The optimized tree stays within 0.1% and returns the same ciphertext. The per-coefficient branch gives a local trace observer every bit of `s`, from which `m = c2 ⊕ Hash_m(s)` and the shared secret follow. Total time reveals only the weight of `s`, which is close to 1024 for honest messages. No extraction was attempted.

Key generation has a related one-time leak in both trees. `poly_inv_xn1_mod3329` inverts the private `f` by a polynomial Euclidean algorithm with degree-dependent loops and an `if (f != 0)` skip (`kem3329.c:163–191`, `:197`), and `mod3329_inv` divides secret-derived values with a data-dependent loop count (`:70–90`). Its consequence is unresolved.

Constant-time fix (easy, hence Low): use the NTT product of the optimized tree, or drop the skip; invert by a fixed-length exponentiation.

### Reproducing

```sh
sh kem-12/reproduce_s_branch.sh
```

The witness builds `ctl_encrypt_3329` from the archived reference and optimized CTL-3329-2048 trees and counts executed instructions under `valgrind --tool=callgrind` for `s` of weight 0 and 2048. It requires the reference count to grow by more than 50%, the optimized count to stay within 1%, and both trees to return the same ciphertext. It exits 77 without `gcc` or `valgrind`.
