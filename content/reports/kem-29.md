<!-- synchronized report: kem-29/report.md -->
Candidate: Polar-KEM
Family: Lattice (polar-code-defined)
Archive: [Polar-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Polar-KEM.zip) (SHA-256: `3ae9d4f1a717fb473e76447014d585cd5d14fe38728f02b1a044cc6a2d03e16d`)

## kem-29-1: The submission ships a complete public-key-only break

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; independent confirmation by LittleQ
Date: 2026-09-21
Original source: [LittleQ's original PKC Forum post on the independent confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AK5EF3YMTS3ND3WAA4DH3VYX5OHQLFGT/)

The submission's own shipped functions provide the complete attack. `polarkem_recover_message(pk, ct, mu)` and `polarkem_derive_valid_secret(mu, ct, ss)` are declared in `polarkem_ct.h` and implemented in the submitted reference source. They recover the encapsulated message and derive the exact shared secret using only public inputs.

The frozen specification does not have this defect: it defines the public key as the disguised basis `B_pk = O * B_red`, keeps the orthogonal transformation `O` in the secret key, and requires decapsulation to apply `O^-1` before decoding. The submitted implementation does not implement that construction. Instead, `polarkem_recover_message` expands a signed permutation from the seed at `pk + POLARKEM_PK_SEED_OFFSET`, making the implementation's decoding transform public. Secret-key material is consulted only to derive the fallback secret for invalid ciphertexts.

Independent execution against the three built libraries called `polarkem_recover_message(pk, ct, mu)` followed by `polarkem_derive_valid_secret(mu, ct, ss)`. The result exactly matched the encapsulator's 16-, 32-, and 64-byte secrets for PolarKEM-128, PolarKEM-256, and PolarKEM-512 without supplying any secret-key bytes.

Anyone observing a public key and ciphertext can therefore recover the session key by calling code shipped by the candidate. This is a total break of the submitted implementation at every level, but it is not an attack on the secret-isometry construction described by the specification.

### Follow-up Analysis

LittleQ's [2026-09-22 PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AK5EF3YMTS3ND3WAA4DH3VYX5OHQLFGT/) independently reports 60/60 matching shared secrets across reference and optimized builds of all three parameter sets. Inspection of the optimized sources confirms that their recovery path also reads its transform seed from the public key.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-29
python3 kem-29/reproduce_public_recovery.py
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## kem-29-2: The specified aligned basis directly exposes the secret isometry

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Polar-KEM core construction, all specified parameter sets
Discovery: Moderate
Exploitation: Polynomial-time exact linear algebra; 0.235 seconds at 128 and 1.169 seconds at 256 in the published experiments
Credit: Yuyang Xiao, Long Chen, and Zhenfeng Zhang
Date: 2026-09-27
Reference: [Xiao, Chen, and Zhang, “Structural Cryptanalysis of Polar-KEM,” ePrint 2026/2211](https://eprint.iacr.org/2026/2211)

Algorithm 1 constructs a polar-code lattice basis from public parameters, reduces it as `B_red=LLL(B)`, and publishes the aligned matrix `B_pk=O*B_red`, where `O` is the secret isometry. It specifies no private randomness before sampling `O`. The reduction parameters and tie handling are not fully fixed; candidate reduced bases can be checked against the public Gram matrix `B_pkᵀB_pk=B_redᵀB_red`. With the corresponding `B_red`, an attacker computes

`O = B_pk * B_red^-1`.

Unlike the general lattice-isomorphism problem, there is no unknown unimodular change of basis: the public matrix exposes the image of every vector in a known complete basis. The paper verifies exact recovery at full 128- and 256-bit dimensions using rational linear algebra. The identity applies to every defined parameter set and recovers the core decapsulation key; a Fujisaki–Okamoto transform cannot hide a secret key that is already a polynomial-time function of the public key.

Section 6.1.1 says the public basis can be represented in Hermite Normal Form. Publishing a canonical HNF instead of the aligned matrix could hide the column correspondence, but that passage conflicts with Algorithm 1's explicit `pk=B_pk=O*B_red`; it does not define an HNF conversion in key generation. Moreover, HNF is defined for integer lattice bases, while Algorithm 1 samples a real orthogonal matrix.

This is distinct from `kem-29-1`: the submitted implementation has an even simpler public recovery function and does not faithfully implement Algorithm 1, whereas this finding breaks the construction written in the specification.

### Reproducing

```sh
python3 kem-29/reproduce_spec_alignment.py
```

The script extracts text from the archived PDF and checks that Algorithm 1 contains the four relevant assignments. It does not run full-size basis recovery; those experiments and timings are reported in the cited ePrint.

## kem-29-3: Decoding radii contradict the specified error and lattice geometry

Severity: High
Status: Confirmed
Layer: Design
Affected: Polar-KEM specification, all three parameter sets; PolarKEM-128 has the direct near-certain honest-failure result
Discovery: Moderate
Exploitation: The specified PolarKEM-128 radius rejects an honest error with probability 0.9965184962; no confidentiality attack is claimed here
Credit: Zhenyu Xiong and Mingsheng Wang
Date: 2026-09-27
Reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §5](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

Table 1 specifies `(N,rho)=(512,15),(1024,31),(2048,63)` and claims decryption-failure probabilities below `2^-128`, `2^-256`, and `2^-512`. The specified ternary error has `Pr[e_i != 0]=1/2`, so `||e||^2` has the distribution `Bin(N,1/2)`. For PolarKEM-128 the radius test therefore rejects with

`Pr[||e|| > 15] = Pr[Bin(512,1/2) > 225] = 0.996518496182011`,

rather than with probability below `2^-128`.

The minimum-distance justification is independently inconsistent. Definition 2.9 includes the unscaled code `C_0` in the polar lattice, and Lemma 2.10 includes `d(C_0)` in the minimum-distance expression. The specified rate progression gives `R_0=1`, hence `C_0=F_2^N`; its unit vectors are lattice vectors and the lattice has `lambda_1=1`. Section 4.5.3 instead drops every code term and asserts `d(Lambda)^2 >= 4^L`. Appendix D also prints the false inequalities `4^5=1024 > 3844` and `4^6=4096 > 15876` for the 256- and 512-bit sets. The submitted failure bounds and unique-decoding premise therefore cannot hold simultaneously. The rectified C implementation instantiates a materially different, level-0-only object and does not repair the normative analysis.

Define one coherent nested code chain, compute its actual minimum distance and decoding region, then choose the error distribution and radius from an exact tail bound and re-establish correctness before making a CCA claim.

### Reproducing

```sh
python3 kem-29/reproduce_spec_defects.py
```

The standard-library-only script checks the normative constants and statements, evaluates the exact binomial tail, and verifies the two printed arithmetic inequalities.

## kem-29-4: Norm-only validation gives one-query ciphertext aliases

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Polar-KEM specification, all three parameter sets
Discovery: Trivial
Exploitation: One decapsulation query on a byte-distinct unit perturbation of the challenge ciphertext
Credit: Zhenyu Xiong and Mingsheng Wang
Date: 2026-09-27
Reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §5](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

Algorithms 6 and 7 derive the valid key only as `K=Extract(m)`. Decapsulation recovers `m_hat`, forms `e_hat=c-Embed(m_hat,pk)`, and accepts whenever `||e_hat||<=rho`; it neither reconstructs the coins from `mu` nor compares a re-encryption, and the valid key does not bind the ciphertext.

Given a challenge `c=Embed(m,pk)+e`, perturb one coordinate by a uniformly random sign to obtain the distinct ciphertext `c'=c+/-u_i`. Whenever the decoder returns the same `m` and the perturbed residual remains inside the decoding ball, Algorithm 7 returns the challenge key `Extract(m)`.

This conclusion does not rely on the specification's inconsistent minimum-distance argument. A signed unit perturbation leaves the changed error coefficient in the specified alphabet `{-1,0,1}` with probability `3/4`; on those outcomes, the perturbed-error distribution has point probability at most twice that of an honest error. Consequently, if the claimed honest decoding-failure probability is `delta`, decoding the perturbation to a different message costs at most `2*delta`. Including the public norm test gives alias probabilities of at least `0.0024956-2^-127`, `0.75-2^-255`, and `0.75-2^-511` for PolarKEM-128, -256, and -512. Thus either these aliases occur with the stated non-negligible probability, or the claimed correctness bound is already false.

One legal CCA query and comparison with the challenge key distinguishes real from random, directly violating the claimed IND-CCA2 security. The attack is unchanged when placeholder hash/XOF functions are replaced by ideal primitives.

Reconstruct the complete encapsulation randomness and compare the received ciphertext byte-for-byte with a canonical re-encryption; derive the valid key from the seed or message together with hashes of the public key and ciphertext.

### Reproducing

```sh
python3 kem-29/reproduce_spec_defects.py
```

The script computes the exact safe-alias probabilities and verifies Algorithm 7's norm-only acceptance and valid-key derivation. This is a mathematical certificate against the specification, not a run against its materially different rectified implementation.
