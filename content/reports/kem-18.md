<!-- synchronized report: kem-18/report.md -->
Candidate: LoongKEM
Family: Lattice (LWE)
Archive: [LoongKEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/LoongKEM.zip) (SHA-256: `a6e5070647a40e7de1bf6e5b085dc1d6423c003a409864fdb303d87f881cec0b`)

## kem-18-1: Partial rejection mask leaks the candidate shared secret

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The decapsulator ORs ciphertext-byte differences into an arbitrary nonzero byte and negates that byte directly to form a selection mask. Except for the value `0x01`, this does not produce the required `0xff` mask. Invalid-ciphertext output is consequently a bitwise mixture of the candidate and fallback keys.

For all four parameter sets, changing ciphertext byte 1 by `0x80` produced an output retaining all seven low bits of every byte of the valid shared secret. Byte 0 is not a universal witness: at the 128- and 256-bit levels it produces only a partial mixture, while it works at the 384- and 512-bit levels. The byte-1 result was reproduced across ten independent key generations per parameter set.

An attacker modifies the IND-CCA challenge ciphertext and compares the retained positions with the challenge key. Agreement distinguishes the real key from a random key with overwhelming probability. This directly violates the claimed IND-CCA security of all four instances.

The comparison result must be normalized to a Boolean and expanded to exactly `0x00` or `0xff` before key selection.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-18
tools/ngcc_attack kem-reject-mask kem-18/lib/libLoong128.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## kem-18-2: Reducible rings project LoongKEM into much smaller SLWE instances

Severity: High
Status: Lead
Layer: Design
Affected: Loong128, Loong384, and Loong512; Loong256's `X^16+1` is integer-irreducible
Discovery: Moderate
Exploitation: Projected-secret recovery is estimated at 2^73.06, 2^103.34, and 2^203.74 operations; full key recovery remains estimator-only
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-28
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JHXFAJR6JLACWVD5ZIWPNP3H7N5OJOGG/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §1](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

The specified rings split over the integers:

```text
X^12+1 = (X^4+1)(X^8-X^4+1)
X^20+1 = (X^4+1)(X^16-X^12+X^8-X^4+1)
X^24+1 = (X^8+1)(X^16-X^8+1).
```

The respective resultants are 81, 625, and 6561, all units modulo `q=8191`, so the two factors are also coprime over the scheme's field. The first public-key block row is entirely over this ring. Reducing it modulo either factor is therefore a public ring homomorphism that preserves shortness, while solving both quotient instances reconstructs the full PKE secret by CRT.

Using the exact alternating-fold secret distribution and a variance-matched model for the folded error and public-key rounding, the current MATZOV BDD estimator gives 73.06, 103.34, and 203.74 bits for the smaller components. These are far below Table 4's 147-, 398-, and 521-bit estimates, whose §5.3 analysis explicitly ignores the algebraic structure. Applying the same marginal model to the complementary components gives full-recovery estimates of 128.59, 365.51, and 399.31 bits; the latter two are below the named 384- and 512-bit targets.

This remains a Lead because coordinates in each complementary quotient have known correlations of magnitude `1/2`, while the standard estimator treats their marginals as independent. The exact decomposition, CRT reconstruction, covariance, and quoted estimator outputs are reproduced, but no covariance-aware full-size key recovery has yet validated the decisive complementary-component step. Under the classification policy, that missing step keeps this candidate-specific recovery path at High rather than Critical.

### Reproducing

Install Martin Albrecht's [lattice-estimator](https://github.com/malb/lattice-estimator) at audited commit `53da5982597709ba0fdf94ea37a84d822310fd84`, then run with a Python interpreter that provides `sage.all`:

```sh
LATTICE_ESTIMATOR_PATH=/path/to/lattice-estimator \
  mamba run -n sage python kem-18/reproduce_reducible_ring.py
```

The script checks the integer factorizations, coprimality modulo 8191, quotient homomorphisms, CRT reconstruction, and exact covariance matrices before reproducing the six MATZOV BDD estimates. Its final `LIMITATION` line records the correlation not modeled by those estimates.

## kem-18-3: Public consistency equations recover Loong128 and Loong256 shared secrets

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Loong128 and Loong256; Loong384 and Loong512 were not evaluated
Discovery: Non-trivial
Exploitation: Practical 48- and 96-variable lattice recoveries followed by 2^12 and 2^16 public re-encryptions
Credit: Tianyuan Xie, on behalf of the openHiTLS team, with GLM-5.3 assistance (corrected 2026-09-30)
Date: 2026-09-29
<!-- Credit correction: On 2026-09-30, the submitter clarified that “GPT-5.5” in the original submission email was a typo; the assistance was GLM-5.3. -->
Original source: [Xie's PKC Forum post and PoC](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VBOUFRS2CDGNLPEAR4ZBKZM4U5YHBTZY/)
Follow-up source: [Xie's LoongKEM256 GitHub issue #23](https://github.com/ngcc-dev/ngcc-harness/issues/23)

LoongKEM publishes the structured matrix equation, naming the matrix `U0` in Algorithm 20; the reference implementation calls the corresponding buffer `U2`:

```text
U0 = Block(r1*A2) + R2*A4 + E4.
```

Negacyclic consistency eliminates the first term and gives 528 public equations in the 48 short coefficients of `r2`. A small Kannan-embedding/BKZ instance recovers one candidate. Subtracting `R2*B2` from the second ciphertext component leaves two plausible message patterns per negacyclic diagonal, or only `2^12 = 4096` messages. Public FO re-encryption identifies the unique message and derives the encapsulated shared secret.

We independently generated a fresh submitted-API key and ciphertext, then gave the attack only the 1,472-byte public key and 1,512-byte ciphertext. It recovered one `r2` candidate and the secret `6ece998be1b9b297d88833700a1c5221`; a separate encapsulation/decapsulation control outside the attack input produced the identical value. A second fresh transcript also reached a unique FO match. This is a public-only recovery of an honest session key and directly violates Loong128's IND-CCA claim, hence Critical.

For Loong256, `N=16` and `k2=6`, so the same public cancellation gives 1,440 equations in 96 short coefficients. Selecting 240 equations produces a 337-dimensional Kannan embedding. Progressive BKZ-20/30/40 recovers `r2`; the 16 negacyclic diagonals then leave `2^16=65,536` message candidates for public FO re-encryption. The attack code and transcript are pinned at commit [`0366a8a`](https://github.com/ifeelok92/ngcc-analysis/tree/0366a8aaf2914d08a5bb8e672e68a87e40a8ef15/instances/loong256).

Our independent replay recovered the posted transcript's shared secret after
130 public re-encryptions. A second run generated a fresh submitted-library
transcript, removed the `SS` line before the attack, and recovered the held-out
secret after 4,389 candidates. Ten further runs—five independent BKZ seeds and
five shuffled public-equation subsets—each found one `r2` candidate, generated
65,536 messages, and recovered the same posted secret. Their lattice phases
took 2,746–3,089 seconds per core under a 12-way parallel load.

### Reproducing

The forum attachment `poc2.zip` has SHA-256 `a358cef75d5ad1b801300fad4a70ab24dfc513ec9bacb2cb8c0e467e3d6ae951`. With Python `fpylll` installed, download and verify it, unpack it, then build its public-input helper against the archived Loong128 source:

```sh
curl -fLO 'https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VBOUFRS2CDGNLPEAR4ZBKZM4U5YHBTZY/attachment/4/poc2.zip'
printf '%s  %s\n' a358cef75d5ad1b801300fad4a70ab24dfc513ec9bacb2cb8c0e467e3d6ae951 poc2.zip | sha256sum -c -
unzip -q poc2.zip
gcc -O2 -Ikem-18/Implementations/Reference_Implementation/Loong128 \
  -o /tmp/dump_loong128_pkct poc2/dump_loong128_pkct.c \
  kem-18/Implementations/Reference_Implementation/Loong128/{KEM_Loong.c,poly.c,auxfunc.c,drng.c}
/tmp/dump_loong128_pkct 66 > /tmp/loong128-pkct.txt
python3 poc2/attack_public_only.py /tmp/loong128-pkct.txt --m 90 --block 40
```

The input file contains exactly `PK` and `CT` lines. The PoC refuses `SK` or expected-`SS` lines and derives the printed shared secret from its recovered message and public key.

For a fresh Loong256 transcript generated from the archived implementation, run:

```sh
PYTHON=/path/to/python-with-fpylll sh kem-18/reproduce_loong256.sh
```

The wrapper keeps the genuine shared secret outside the attack input, runs the
pinned public-data recovery, and compares the recovered value only after the
attack has finished. It applies a compatibility-only float conversion to the
PoC's post-BKZ RMS diagnostic on Sage builds where `fpylll` returns Sage
integers; candidate recovery is unchanged. Our fully loaded runs took about
46–52 minutes per core.

## kem-18-4: The rejection key hashes the re-encryption instead of the received ciphertext

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All four parameter sets, reference, optimized and additional implementations
Discovery: Moderate
Exploitation: Complete decryption secret recovered on all four parameter sets from decapsulation queries alone; each recovery matches the secret parsed from sk, and an equivalent decapsulation key rebuilt from the public key and the recovered secret returns the library's own shared secret for a fresh honest ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Algorithm 24 (p. 21), line 4, sets the implicit-rejection key to `K̄ = H(salt‖c)` over the received ciphertext `c`. The code instead re-encrypts the decrypted message into `salt_ct+SEED_BYTES` (`KEM_Loong.c:289`) and hashes `salt‖c′` over that re-encryption (`:295`); the received `ct` is never hashed. These line numbers hold for all four sets, and the `kem_dec` function is identical in the reference, optimized and additional trees; the runtime test uses the reference build.

Every invalid ciphertext that decrypts to a given message `M′` therefore receives the same rejection output `H(salt‖Enc(pk, M′, γ′))`. The decapsulation oracle consequently answers whether two submitted ciphertexts decrypt to the same message, which is a plaintext-checking oracle on the static secret key. Plaintext-checking oracles are the standard starting point for key recovery against LWE-type KEMs, and the Fujisaki–Okamoto argument behind the claimed IND-CCA2 security (pp. 23, 26–27) does not cover this rejection rule.

The test flips bit 0 of one ciphertext byte. The decapsulator ORs the byte differences between `ct` and `c′` and negates the result as its selection mask (`:297–304`). When the flipped ciphertext still decrypts to the challenge message, `c′ = c*`, the OR is exactly `0x01` and its negation is `0xff`. The output is then the whole rejection key, not a bitwise mixture of it with the challenge key. This isolates the rejection-key binding from the mask construction. A fully normalized mask would still return the same `H(salt‖c*)` for every such ciphertext.

On the four prebuilt libraries, 12 to 16 of 16 single bit-0 flips of a challenge ciphertext returned one identical value, which was not the challenge key. Recomputing the hash with the code's SM3 XOF shows that this value is `H(salt‖c*)`, and none of the 16 outputs equals the specified `H(salt‖c_j)`. The remaining flips change the decrypted message and are rejected with other values. The mauled challenge does not return `K*`. The defect therefore gives an oracle whose target is the static secret key.

Reclassified from Medium to Critical on 2026-10-18 after full decryption-secret recovery. The coefficient-boundary method is adapted from earlier ML-KEM plaintext-checking-oracle key-recovery experiments. LoongKEM stores the secret directly in the coefficient domain (`decode_noise_vector`, `KEM_Loong.c`), and the message is an `N×N` matrix, so sweeping one compressed `V` coefficient moves exactly one message bit and turns the whole-message oracle into a per-bit boundary oracle. Perturbing one compressed `u` coefficient shifts the first secret block `s1` (`K1` degree-`N` polynomials) read from the first matrix row; perturbing one compressed `U` coefficient shifts the second block `s2` (`K2` polynomials, through the block negacyclic matrix `S2`) read from the same row. The `V`-compression boundary measured before and after bounded `±` perturbations pins each small secret coefficient exactly. The attack queries only the prebuilt `lib/*.so` through the uniform ABI and parses `sk` only for the final check. It recovered the complete secret of Loong128 (624 coefficients), Loong256 (1120), Loong384 (1600) and Loong512 (2160); each recovery matches the secret parsed from `sk` coefficient for coefficient. An equivalent decapsulation key is then built without copying any byte of the original: the recovered secret, the public key, `SM3(pk)` and an all-zero fallback salt. It decapsulates a fresh honest ciphertext to the library's own shared secret, and the same construction with one deliberately wrong coefficient does not. Because the fallback salt is arbitrary, the rebuilt key differs from the original only in its rejection outputs. Query counts and run times are given under Reproducing below.

The frozen implementation's oracle arises from the combination of two defects: the rejection key is bound to the re-encryption of the decrypted message rather than to the received ciphertext (this finding), and the selection mask is the bitwise negation of a nonzero difference byte rather than a normalised all-ones mask. The reproducer's predicate — `output == K* ⊕ (mask & (C0 ⊕ K*))`, with `mask` computed from the attacker-known `ct ⊕ c*` and `C0 = H(salt‖c*)` read once — holds because both are present. Arguing from the source alone, either defect alone is already sufficient for a plaintext-checking oracle on the static key. With a correct all-ones mask but this rejection rule, every invalid ciphertext returns `H(salt‖Enc(pk, M′, γ′))`, a value that depends only on the decrypted `M′`; it equals the fixed constant `H(salt‖c*)` for the ciphertexts that decrypt to the base message, and otherwise only by a negligible accidental collision, which is the oracle. With a correct `H(salt‖ct)` rejection rule but this partial mask, the mask leaves some byte positions holding `k_gamma = H(M′‖H(pk))` unmasked; those positions equal the known `K*` when `M′` is the base message, and otherwise only by a negligible accidental match, which is again the oracle. Eliminating the demonstrated oracle therefore requires fixing both.

Hashing the received ciphertext, `H(salt‖ct)`, as Algorithm 24 specifies, fixes this defect. Eliminating the demonstrated oracle also requires expanding the comparison result to a Boolean `0x00`/`0xff` selection mask.

### Reproducing

```sh
python3 kem-18/reproduce_rejection_reencryption.py
sh kem-18/reproduce_pco_key_recovery.sh            # full key recovery; NGCC_LONG=1 for all four sets
```

The first script shows the rejection-key collision directly: it uses the prebuilt `kem-18/lib/*.so` through ctypes, checks that honest decapsulation returns `K*` and that 16 bit-0 flips of `c*` give at least four identical outputs different from `K*`, and, when `hashlib` provides SM3, confirms the value is `H(salt‖c*)`. It runs in about two seconds.

The second script performs the full key recovery. It builds a small C attack (`kem-18/pco_loong.c`) in a temporary directory and queries only the prebuilt library through the uniform ABI loaded with `dlopen`; it never links the submission's internal decrypt. It prints, per set, that honest decapsulation matches, the recovered-versus-true coefficient count, the rebuilt-key re-decapsulation check, and the rejected-wrong-coefficient control, with the setup and recovery-batch query counts and wall time. The setup is the honest check plus about 80–90 decapsulations of bit-flipped ciphertexts that identify `C0`; it is reported separately from the recovery batch. By default it recovers the smallest set (Loong128), reported both for a single-process sequential run and for a fork-parallel run; `NGCC_LONG=1` recovers all four sets. The batch queries are independent, so the parallel run uses `fork()` workers (the decapsulator reads no mutable global state). With 24 workers, the recovery batch took 7.5 s (60,512 queries) for Loong128, 53 s (224,400) for Loong256, 231 s (320,500) for Loong384 and 322 s (276,864) for Loong512; the sequential Loong128 run took 135 s.
