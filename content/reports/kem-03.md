<!-- synchronized report: kem-03/report.md -->
Candidate: BAG-Loong
Family: Code-based (rank metric)
Archive: [BAG-Loong.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BAG-Loong.zip) (SHA-256: `2795fd57d3d00791652256362b4a21982116d3aad1fb63633dac923e0e76e05b`)

## kem-03-1: Secret-dependent pivoting in the Gabidulin decoder

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all four parameter sets
Discovery: Moderate
Exploitation: Local control-flow/cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Decapsulation forms a rank-code word by multiplying the public ciphertext component by secret `x` and adding the second ciphertext component (`src/loong_pke.c:1003-1014`). The Gabidulin decoder then searches for a pivot with a discrepancy-dependent `while` loop, swaps at the chosen index, and branches into different polynomial-update paths (`src/gabidulin.c:213-279`). The executed path and addresses thus depend on the recipient secret, not just public ciphertext. A co-resident timing/cache observer can learn information about the intermediate. No inversion from observed pivot sequences to the private vector, full key-recovery attack, or remote channel is shown; a key-dependent pivot is not by itself a Critical break.

Constant-time fix (moderate, hence Medium): the pivot search loop, data-dependent swaps and update branches must be replaced by a fixed-iteration decoder with masked pivot selection and swaps. That technique is published (Bettaieb, Bidoux, Gaborit and Marcatel, PQCrypto 2019) and has moderate cost, so this is a substantial rewrite without a significant performance loss.

### Reproducing

The source-level witness is the decapsulation call in `src/loong_kem.c:217-218`, the secret-key product in `src/loong_pke.c:1003-1014`, and the value-dependent pivot loop in `src/gabidulin.c:213-279` under `Implementations/Reference_Implementation/Loong-Block-ms-128/`. The same files occur in the other reference parameter directories. See `constant_time.md` for the secret/public classification.

## kem-03-2: The rejection key does not bind the received ciphertext

Severity: High
Status: Confirmed
Layer: Design
Affected: All BAG-Loong parameter sets
Discovery: Moderate
Exploitation: Observable rejection keys give a plaintext-checking and decoding-failure oracle; challenge-key recovery is unshown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

Algorithm 2 (§1.4) specifies `K(ξ, ct')` on rejection, where `ct'` is the re-encryption of the decrypted message rather than the received ciphertext. The code follows it (`loong_kem.c:229–246`). Distinct invalid ciphertexts with the same decryption therefore share a rejection key, exposing a plaintext-checking and decoding-failure oracle when keys are observable. This departs from standard Fujisaki–Okamoto rejection, so the stated IND-CCA2 proof does not establish the submitted construction's claim. A mauled challenge returns `K(ξ, c*)`, not the challenge key `K*`; the witness demonstrates rejection-key collisions, not challenge-key recovery or a full IND-CCA2 attack.

### Reproducing

```sh
python3 kem-03/reproduce_rejection_key.py kem-03/lib/libBAG-Loong-128.so
```

## kem-03-3: Public support spaces reduce secret-key recovery to linear algebra

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Moderate
Exploitation: 0.049–0.988 seconds for public-key recovery in the published Python experiments
Credit: Zihan Liu
Date: 2026-09-27
Reference: [Liu, “Linear Key Recovery in the BAG-Loong Reference Implementation,” ePrint 2026/2223](https://eprint.iacr.org/2026/2223)

The specification calls for secret random support spaces for the PKE matrices `X` and `Y`. While choosing those supports, the reference sampler ignores its XOF reader and builds one public pool `1,beta,beta^2,...`; fixed overlapping slices are the two supports. The matrix coefficients are still sampled from the seed-dependent XOF. Expanding the public relation `S=H*X+Y` over `F_2` and projecting away the known support of `Y` leaves a binary linear system for `X`. Encryption uses the same fixed-pool sampler, so the supports of `R1`, `E`, and `R2` are public too.

The paper gives two independent solvers. On all 40 supplied KAT records, their reduced matrices had full column rank and recovered `X` exactly. A KEM secret key assembled from the public seed, recovered `X`, public key, and an arbitrary rejection secret decapsulated every valid KAT ciphertext to the reference session key; replacing `X` by zero rejected. Mean Python recovery times were 0.049, 0.171, 0.432, and 0.988 seconds for the 128-, 256-, 384-, and 512-bit sets. This is complete public-key recovery of the decryption capability, independent of decoder timing.

An independent source-linked witness recovered `X` byte for byte from five fresh BAG-Loong-128 public keys. Every column's binary system had rank 210/210; the five recoveries took 0.66–0.68 seconds each on this host. The secret key was used only afterward to check the recovered bytes.

### Reproducing

```sh
python3 kem-03/reproduce_public_supports.py
make -C kem-03 reproduce-public-supports
```

The first command checks all four archived samplers, the `S=H*X+Y` source operation, and the reported reduced-system dimensions. The second builds the submitted 128-bit source and recovers `X` from five fresh public keys, requiring full rank and a byte-for-byte match with the secret used to generate each key. The ePrint reports the full 40-key elimination and unmodified-decapsulation experiment; its solver code was not released with the paper.

## kem-03-4: Merged support reduces rank-decoding costs below three claimed levels

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BAG-Loong-256, -384, and -512 parameters
Discovery: Non-trivial
Exploitation: Estimated classical key-recovery costs of 2^243.3, 2^333.3, and 2^432.9; no full-parameter attack executed
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/632RW5CKKAJXJ3GBZ7ZL6RE7CLCVYFGQ/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/e6b324cd411758ab5b18a08de999276bf260c9aa/bag-loong-spec-level)

The key-recovery instance in Equation (1) (physical p. 11) has error rank `t1+t2-g`, because the two secret supports share a `g`-dimensional intersection. The matching analysis in §3.3.2 and Table 5 instead price two separate ranks `t1+t2`. Measured keys have merged ranks 6, 8, 9, and 10. CryptographicEstimators 2.1.1 gives conservative `omega=3` key-recovery costs of `2^243.3`, `2^333.3`, and `2^432.9` for the affected sets, all below their claims. The reported `2^403.5` cost for the 512-bit ciphertext instance assumes its message is already known, so it is not used here as a KEM attack bound. The 128-bit set clears its target for `omega=2.81` and 3.

The pinned package measures the merged ranks on 80 keys generated with the specified random-support distribution and performs complete reduced-scale recovery of `X`, with controls for the separate-block model. It does not execute the full-parameter attacks.

### Reproducing

```sh
./kem-03/reproduce_spec_level.sh
```

The wrapper pins the public package, runs real-key measurements, reduced-scale recoveries, and a closed-form certificate. It checks the quoted estimator values only when the optional CryptographicEstimators dependency is installed; the full package can take about 20 minutes.

## kem-03-5: The decoder rejects supports permitted by the specification

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All four BAG-Loong reference parameter sets when sampling follows Algorithm 1
Discovery: Non-trivial
Exploitation: The submitted decoder rejected 40/40 honest KEM round trips with a specification-conforming sampler
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/632RW5CKKAJXJ3GBZ7ZL6RE7CLCVYFGQ/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/e6b324cd411758ab5b18a08de999276bf260c9aa/bag-loong-spec-level)

Algorithm 1 (physical p. 6) requires random support spaces with the listed intersection. Under that distribution, the residual tail has support dimension 38, 57, 72, and 82, above the listed `epsilon=33,51,66,73` (Table 1, physical p. 8). In the specification `epsilon` is a minimum used in the failure analysis, not a maximum decoder input. The reference decoder nevertheless rejects when `tail_rank > epsilon` (`augabidulin.c:145`).

A source-level repair that makes the sampler follow all three specified support conditions exceeded `epsilon` in 400/400 ciphertexts and produced 0/40 correct KEM round trips. In a separate patch check, lifting the decoder's cap restored 40/40; the archived nonconforming sampler also passed 40/40. This is a limited implementation/conformance defect, not a failure of the specified augmented code. The tail-dimension formula follows Liu, ePrint 2026/2223, Equation (10).

### Reproducing

```sh
./kem-03/reproduce_spec_level.sh
```
