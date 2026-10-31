<!-- synchronized report: kem-09/report.md -->
Candidate: CheetahKEM
Family: Lattice (Ring/Module-LWE)
Archive: [CheetahKEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CheetahKEM.zip) (SHA-256: `fc321e46bac9c387535e2053bed560eac3d3cd88ba9bebc154f5bf68dd47dcd1`)

## kem-09-1: Partial rejection mask leaks the candidate shared secret

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The decapsulator ORs ciphertext-byte differences into an arbitrary nonzero byte and then uses its negation directly as a selection mask. Negating a nonzero byte produces `0xff` only when that byte is `0x01`; other values select a bitwise mixture of the valid candidate key and the rejection key.

For all four parameter sets, changing ciphertext byte 1 by `0x80` produced a rejection output retaining all seven low bits of every byte of the valid shared secret. Byte 0 is not a universal witness: at the 128- and 256-bit levels it produces only a partial mixture, while it works at the 384- and 512-bit levels. The permanent `kem-reject-mask` test reproduced a byte-1 witness for every tested key generation.

An IND-CCA attacker modifies the challenge ciphertext and compares the retained bit positions with the challenge key. For a real challenge they agree; for a random challenge the false-match probability is negligible. This is a direct distinguisher against all four claimed IND-CCA instances.

The fix is to normalize every nonzero comparison result to an all-ones mask before selecting between the candidate and rejection secrets.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-09
tools/ngcc_attack kem-reject-mask kem-09/lib/libCheetah128.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## kem-09-2: A degree-128 quotient defeats the full-dimension MLWE estimates

Severity: High
Status: Lead
Layer: Design
Affected: All four parameter sets
Discovery: Moderate
Exploitation: Estimated at 2^27.7, 2^67.7, 2^99.3, and 2^133.4 operations
Credit: XuHaomeng
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/IKMFXEEH5K427JC75E7364RNOJEO5OK7/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §2](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

The specified ring polynomial is reducible: `X^640+1 = (X^128+1)(X^512-X^384+X^256-X^128+1)`. Reducing a public MLWE sample modulo `X^128+1` is the public alternating fold `a[j]-a[j+128]+a[j+256]-a[j+384]+a[j+512]`. It reduces the scalar secret dimension from `640k` to `128k`; five independent `CBD(eta)` coefficients fold to `CBD(5*eta)`, and public-key compression noise folds in the same way.

Re-running `lattice-estimator` with that quotient distribution reproduces XuHaomeng's [mailing-list estimates](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/IKMFXEEH5K427JC75E7364RNOJEO5OK7/): uSVP costs of 27.7, 67.7, 99.3, and 133.4 bits, versus the specification's 159, 307, 426, and 541 bits. This establishes a much cheaper distinguisher for the underlying structured samples and invalidates estimates that treat all `640k` coordinates as one irreducible component.

This remains a Lead because a complete IND-CCA attack on the KEM has not been constructed. Full secret recovery also requires solving the residual degree-512 component; the post explicitly leaves that cost unresolved.

Xiong and Wang independently reproduce the quotient, estimator figures, and reduced toy recoveries. Their stronger statement that distinguishing the projected public-key distribution by itself breaks IND-CPA reverses the direction of the usual SLWE reduction: it does not provide a challenge-message or shared-key distinguisher for an honestly generated public key. The paper therefore strengthens the structural and experimental evidence but does not close the full-recovery gap recorded above.

### Reproducing

Install Martin Albrecht's [lattice-estimator](https://github.com/malb/lattice-estimator)
at the audited commit `53da5982597709ba0fdf94ea37a84d822310fd84`, then run
the script with Sage's Python and point it at that checkout:

```sh
LATTICE_ESTIMATOR_PATH=/path/to/lattice-estimator \
  mamba run -n sage python kem-09/reproduce_quotient_estimate.py
```

The script checks the factorization and quotient homomorphism, then instantiates the estimator with the folded secret, error, and compression distributions.
The command uses this host's Sage environment; elsewhere, any Python with `sage.all` importable can run the script with `LATTICE_ESTIMATOR_PATH` set.

## kem-09-3: Cheetah's decryption-failure analysis omits public-key rounding

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All four CheetahKEM parameter sets
Discovery: Moderate
Exploitation: Submitted failure estimates omit a noise term; actual DFR and attack impact unmeasured
Credit: Yijian Liu (with AI assistance)
Date: 2026-09-24
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5TLZROCK6ZQKG6HTV3PNNESJKICDDKGE/)

Algorithm 15 publishes `b' = Compress(A·s+e)`, and Algorithm 16 encrypts with `Decompress(b')`. Writing the nonzero public-key rounding error as `e_pk = Decompress(b')-(A·s+e)`, the decryption noise contains `e_pk·r`. Section 2.2's correctness derivation substitutes `b·r` as though no public-key compression occurred, and its Gaussian DFR formula includes `e·r`, `s·e1`, and ciphertext-rounding terms but omits `e_pk·r`. The source performs the same compression/decompression (`KEM_Cheetah.c:96,123`).

Liu estimates corrected log2 failure rates of about −77.85, −51.54, −115.07, and −198.96, versus the submission's −129, −176, −189, and −243. Those **numerical** estimates have not been independently reproduced or measured against the full KEM here. The confirmed result is the missing nonzero term, which invalidates the quoted derivation; this report does not claim a practical decapsulation attack.

Follow-up analysis: [Xiao, ePrint 2026/2250, §§10–11](https://eprint.iacr.org/archive/2026/2250/1790598276.pdf) independently derives the omitted `e_pk*r` term and models rates near `2^-79.1`, `2^-51.8`, `2^-116.1` and `2^-201.0`. Its far tails remain model-based and it gives no completed key recovery, so this additional evidence does not change the classification.

### Reproducing

```sh
python3 kem-09/reproduce_pk_compression_noise.py
```

The script exactly enumerates the source's one-coefficient public-key rounding error for each `db` and confirms a nonzero `e_pk·r` variance under the submission's independent-coefficient surrogate. It does not compute a failure tail or validate Liu's four exponents.

## kem-09-4: The rejection key hashes the re-encryption instead of the received ciphertext

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All four parameter sets, reference, optimized and additional implementations
Discovery: Moderate
Exploitation: Complete decryption secret recovered on all four parameter sets from decapsulation queries alone; each recovery matches the secret parsed from sk, and an equivalent decapsulation key rebuilt from the public key and the recovered secret returns the library's own shared secret for a fresh honest ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Algorithm 20 (p. 18), line 4, sets the implicit-rejection key to `K̄ = H(salt‖c)` over the received ciphertext `c`. The code instead re-encrypts the decrypted message into `salt_ct+SEED_BYTES` (`KEM_Cheetah.c:277`) and hashes `salt‖c′` over that re-encryption (`:283`); the received `ct` is never hashed. The line numbers are for Cheetah128 and Cheetah256; Cheetah384 has them at `:276`/`:282` and Cheetah512 at `:280`/`:286`. The `kem_dec` function is identical in the reference, optimized and additional trees of all four sets; the runtime test uses the reference build.

Every invalid ciphertext that decrypts to a given message `m′` therefore receives the same rejection output `H(salt‖Enc(pk, m′, γ′))`. The decapsulation oracle consequently answers whether two submitted ciphertexts decrypt to the same message, which is a plaintext-checking oracle on the static secret key. Plaintext-checking oracles are the standard starting point for key recovery against LWE-based KEMs, and the Fujisaki–Okamoto argument behind the claimed IND-CCA security (pp. 19, 22–23) does not cover this rejection rule.

The test flips bit 0 of one ciphertext byte. The decapsulator ORs the byte differences between `ct` and `c′` and negates the result as its selection mask (`:285–292`). When the flipped ciphertext still decrypts to the challenge message, `c′ = c*`, the OR is exactly `0x01` and its negation is `0xff`. The output is then the whole rejection key, not a bitwise mixture of it with the challenge key. This isolates the rejection-key binding from the mask construction. A fully normalized mask would still return the same `H(salt‖c*)` for every such ciphertext.

On the four prebuilt libraries, 10 to 13 of 16 single bit-0 flips of a challenge ciphertext returned one identical value, which was not the challenge key. Recomputing the hash with the code's SM3 XOF shows that this value is `H(salt‖c*)`, and none of the 16 outputs equals the specified `H(salt‖c_j)`. The remaining flips change the decrypted message and are rejected with other values. The mauled challenge does not return `K*`. The defect therefore gives an oracle whose target is the static secret key.

Reclassified from Medium to Critical on 2026-10-18 after full decryption-secret recovery. The coefficient-boundary method is adapted from earlier ML-KEM plaintext-checking-oracle key-recovery experiments. Changing one compressed `v` coefficient moves exactly one decrypted message coordinate, so the whole-message oracle becomes a per-coordinate boundary oracle; perturbing one compressed `u` monomial `x^p` shifts decryption coordinate `i` by `±D·s[(i−p) mod 640]` in the degree-640 ring (the negacyclic product the reference computes through its NTT), so sweeping `p` over `{0,128,…}` reads every coefficient of every secret polynomial from the 128–512 decrypted coordinates. The `v`-compression boundary measured before and after bounded `±` perturbations pins each small secret coefficient exactly. The attack queries only the prebuilt `lib/*.so` through the uniform ABI and parses `sk` only for the final check. It recovered the complete secret polynomial of Cheetah128 (640 coefficients), Cheetah256 (1280), Cheetah384 (1920) and Cheetah512 (2560); each recovery matches the secret parsed from `sk` coefficient for coefficient. An equivalent decapsulation key is then built without copying any byte of the original: the recovered secret, the public key, `SM3(pk)` and an all-zero fallback salt. It decapsulates a fresh honest ciphertext to the library's own shared secret, and the same construction with one deliberately wrong coefficient does not. Because the fallback salt is arbitrary, the rebuilt key differs from the original only in its rejection outputs. Query counts and run times are given under Reproducing below.

The frozen implementation's oracle arises from the combination of two defects: the rejection key is bound to the re-encryption of the decrypted message rather than to the received ciphertext (this finding), and the selection mask is the bitwise negation of a nonzero difference byte rather than a normalised all-ones mask. The reproducer's predicate — `output == K* ⊕ (mask & (C0 ⊕ K*))`, with `mask` computed from the attacker-known `ct ⊕ c*` and `C0 = H(salt‖c*)` read once — holds because both are present. Arguing from the source alone, either defect alone is already sufficient for a plaintext-checking oracle on the static key. With a correct all-ones mask but this rejection rule, every invalid ciphertext returns `H(salt‖Enc(pk, m′, γ′))`, a value that depends only on the decrypted `m′`; it equals the fixed constant `H(salt‖c*)` for the ciphertexts that decrypt to the base message, and otherwise only by a negligible accidental collision, which is the oracle. With a correct `H(salt‖ct)` rejection rule but this partial mask, the mask leaves some byte positions holding `k_gamma = H(m′‖H(pk))` unmasked; those positions equal the known `K*` when `m′` is the base message, and otherwise only by a negligible accidental match, which is again the oracle. Eliminating the demonstrated oracle therefore requires fixing both.

Hashing the received ciphertext, `H(salt‖ct)`, as Algorithm 20 specifies, fixes this defect. Eliminating the demonstrated oracle also requires expanding the comparison result to a Boolean `0x00`/`0xff` selection mask.

### Reproducing

```sh
python3 kem-09/reproduce_rejection_reencryption.py
sh kem-09/reproduce_pco_key_recovery.sh            # full key recovery; NGCC_LONG=1 for all four sets
```

The first script shows the rejection-key collision directly: it uses the prebuilt `kem-09/lib/*.so` through ctypes, checks that honest decapsulation returns `K*` and that 16 bit-0 flips of `c*` give at least four identical outputs different from `K*`, and, when `hashlib` provides SM3, confirms the value is `H(salt‖c*)`. It runs in under a second.

The second script performs the full key recovery. It builds a small C attack (`kem-09/pco_cheetah.c`) in a temporary directory and queries only the prebuilt library through the uniform ABI loaded with `dlopen`; it never links the submission's internal decrypt. It prints, per set, that honest decapsulation matches, the recovered-versus-true coefficient count, the rebuilt-key re-decapsulation check, and the rejected-wrong-coefficient control, with the setup and recovery-batch query counts and wall time. The setup is the honest check plus about 80–90 decapsulations of bit-flipped ciphertexts that identify `C0`; it is reported separately from the recovery batch. By default it recovers the smallest set (Cheetah128), reported both for a single-process sequential run and for a fork-parallel run; `NGCC_LONG=1` recovers all four sets. The batch queries are independent, so the parallel run uses `fork()` workers (the decapsulator reads no mutable global state). With 24 workers, the recovery batch took 1.2 s (83,968 queries) for Cheetah128, 4.8 s (225,280) for Cheetah256, 20.8 s (448,512) for Cheetah384 and 76 s (1,088,000) for Cheetah512; the sequential Cheetah128 run took 15 s.

## kem-09-5: Natural decryption failures recover the secret key

Severity: Critical
Status: Probable
Layer: Design
Affected: Cheetah128 and Cheetah256; for Cheetah384 and Cheetah512 the estimated cost of this route far exceeds the target within 2^80 queries
Discovery: Non-trivial
Exploitation: Estimated 2^63.1 decapsulation queries for Cheetah256 and 2^77.3–2^79.8 queries from about 2^95 encapsulations for Cheetah128; key recovery executed on simulated failures only
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-31

Algorithm 15 publishes `Compress(A·s+e)` and Algorithm 16 encrypts with its decompression, so the decryption noise contains the public-key rounding term `e_pk·r`. With that term, the exact per-coefficient noise law gives log2 failure rates of −77.84, −51.54, −115.06 and −198.95 for the four sets, against Table 2's −129, −176, −189 and −243. The model's Cheetah256 noise standard deviation (245.5) matches the 244.1 measured on honest encapsulations through the reference code.

An attacker that encapsulates honestly knows `K` and sees a failure as a decapsulation output different from `K`. It also knows its own `r`, `e1`, `e2` and ciphertext rounding errors, and the failure condition is linear in the secret. Expectation-maximisation over the unknown failing position and sign, followed by a public-key consistency check, recovers `s`, which decapsulates any challenge. Cheetah256 needs about 3,000 failures, or 2^63.1 honest queries without preselection. Cheetah128 needs about 1,500 failures from ciphertexts preselected for large `r` and `e1` norms: 2^77.3 queries under the exact norm-tilted law (2^79.8 under a Gaussian model), selected from about 2^95 honest encapsulations by a Cramér estimate. That is below 2^128 unless one encapsulation costs more than 2^33 operations. For Cheetah384 and Cheetah512 the same preselection needs about 2^748 and 2^5351 encapsulations to stay within 2^80 queries.

No 2^63-query run was performed. The failures were drawn from the exact failure-conditioned noise law under the usual independent uniform-rounding model, not from real ciphertexts, and the model was compared with the reference code only through the noise standard deviation.

### Reproducing

```sh
python3 kem-09/reproduce_failure_rate.py     # requires numpy
python3 kem-09/reproduce_boost_cost.py       # requires numpy and scipy
sh kem-09/reproduce_failure_recovery.sh      # NGCC_LONG=1 adds boosted Cheetah128
```

The first script computes the exact noise law and failure rates with and without `e_pk`. The second computes the preselection costs above, including the exact tilted Cheetah128 rate, in under a minute. The third measures the noise of 20,000 Cheetah256 encapsulations through the reference `KEM_Cheetah.c`, then recovers a fresh Cheetah256 secret exactly from 3,000 simulated failures in about 40 seconds; `NGCC_LONG=1` also recovers a Cheetah128 secret from 1,500 boosted failures.
