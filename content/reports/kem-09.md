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

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: All four parameter sets, reference, optimized and additional implementations
Discovery: Moderate
Exploitation: Distinct invalid ciphertexts with the same decryption received one identical rejection key on all four sets; no key recovery or challenge-key distinguisher was run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Algorithm 20 (p. 18), line 4, sets the implicit-rejection key to `K̄ = H(salt‖c)` over the received ciphertext `c`. The code instead re-encrypts the decrypted message into `salt_ct+SEED_BYTES` (`KEM_Cheetah.c:277`) and hashes `salt‖c′` over that re-encryption (`:283`); the received `ct` is never hashed. The line numbers are for Cheetah128 and Cheetah256; Cheetah384 has them at `:276`/`:282` and Cheetah512 at `:280`/`:286`. The `kem_dec` function is identical in the reference, optimized and additional trees of all four sets; the runtime test uses the reference build.

Every invalid ciphertext that decrypts to a given message `m′` therefore receives the same rejection output `H(salt‖Enc(pk, m′, γ′))`. The decapsulation oracle consequently answers whether two submitted ciphertexts decrypt to the same message, which is a plaintext-checking oracle on the static secret key. Plaintext-checking oracles are the standard starting point for key recovery against LWE-based KEMs, and the Fujisaki–Okamoto argument behind the claimed IND-CCA security (pp. 19, 22–23) does not cover this rejection rule.

The test flips bit 0 of one ciphertext byte. The decapsulator ORs the byte differences between `ct` and `c′` and negates the result as its selection mask (`:285–292`). When the flipped ciphertext still decrypts to the challenge message, `c′ = c*`, the OR is exactly `0x01` and its negation is `0xff`. The output is then the whole rejection key, not a bitwise mixture of it with the challenge key. This isolates the rejection-key binding from the mask construction. A fully normalized mask would still return the same `H(salt‖c*)` for every such ciphertext.

On the four prebuilt libraries, 10 to 13 of 16 single bit-0 flips of a challenge ciphertext returned one identical value, which was not the challenge key. Recomputing the hash with the code's SM3 XOF shows that this value is `H(salt‖c*)`, and none of the 16 outputs equals the specified `H(salt‖c_j)`. The remaining flips change the decrypted message and are rejected with other values. The mauled challenge does not return `K*`. The defect therefore gives an oracle, not challenge-key recovery, and no candidate-specific key-recovery attack was run.

The fix is to hash the received ciphertext, `H(salt‖ct)`, as Algorithm 20 specifies.

### Reproducing

```sh
python3 kem-09/reproduce_rejection_reencryption.py
```

The script uses the prebuilt `kem-09/lib/*.so` through ctypes. For each set it checks that honest decapsulation returns `K*` and that 16 bit-0 flips of `c*` give at least four identical outputs different from `K*`. As controls, bit-0 flips of a second, independent encapsulation collide on a different value, and a heavy mutation of `c*` does not return the collision value. When `hashlib` provides SM3, it also confirms that the value is `H(salt‖c*)` and never `H(salt‖c_j)`. It runs in under a second.
