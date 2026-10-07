<!-- synchronized report: kem-26/report.md -->
Candidate: NSS-HQC
Family: Code-based (HQC-type quasi-cyclic codes)
Archive: [NSS-HQC.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NSS-HQC.zip) (SHA-256: `033994e27bf0dc824078593a98eb51465f979b1bca0932cabb29be6626447638`)

## kem-26-1: Fixed-weight parity falsifies the DQCSD and JPCI assumptions

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All four NSS-HQC parameter sets and the IND-CPA/IND-CCA2 reductions
Discovery: Trivial
Exploitation: One parity computation distinguishes the assumed distribution; no message or key recovery demonstrated
Credit: Information Security Center, Academy of Mathematics and Systems Science, Chinese Academy of Sciences
Date: 2026-09-30
Original source: [AMSS PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DGP2J3ZUZJYNC4COYWQQ77L42OOFNCP7/)

The DQCSD assumption compares `(h, r1+h*r2)` with uniform ring elements, and the JPCI assumption used by Lemma 16 contains the same first ciphertext component `u`. In `F2[x]/(x^n-1)`, parity is evaluation at `x=1`, so `parity(a*b)=parity(a)·parity(b)`. NSS-HQC-128 and -256 give both `r1` and `r2` even fixed weight, forcing `parity(u)=0`; uniform `u` has either parity with probability one half.

Further extension to the AMSS analysis: the same distinguisher covers the odd-weight 384- and 512-bit sets. There `parity(u)=1+parity(h)`, which is also public and deterministic. Thus all four stated DQCSD/JPCI instances are trivially distinguishable from the distributions used in the reductions. This invalidates the submitted proof route but does not by itself distinguish encrypted messages or recover a secret, hence Medium rather than Critical.

### Reproducing

```sh
python3 kem-26/reproduce_parity.py
```

The witness produces 64 NSS-HQC-256 ciphertexts with the submitted library: every `u` has even parity, while a deterministic uniform-string control contains both parities. The other levels follow exactly from their fixed weights 66, 106, 159, and 213 and the identity above.

## kem-26-2: NSS-HQC-256 failures enable reported equivalent-key recovery

Severity: Critical
Status: Probable
Layer: Design
Affected: NSS-HQC-256 parameters, DFR analysis, and submitted reference implementation; higher-set recovery not executed
Discovery: Non-trivial
Exploitation: Sun reports equivalent-key recovery after about 2^27 adaptive decapsulations; the full recovery has not been independently replayed
Credit: Information Security Center, Academy of Mathematics and Systems Science, Chinese Academy of Sciences; failure-oracle key-recovery extension by Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [AMSS PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DGP2J3ZUZJYNC4COYWQQ77L42OOFNCP7/)
Follow-up source: [Sun's NSS-HQC failure-oracle recovery post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PA6JZ4YGBB3GE6FEL6BSXLAGMUGIPBJ2/)

The specification selects every parameter set under `DFR_NSS < 2^-128` (§3.6) and uses that bound in its IND-CCA2 loss. Its calculation replaces the five-bit compressor's correlated errors with a binary-symmetric-channel proxy. Equation (68) is also labelled an upper bound although it counts only error patterns matching nonzero RM codewords; the forum gives `7.53·10^-45` at crossover probability `1/4`, while one omitted failure event alone has probability at least `4.59·10^-6`.

The mismatch is observable in the complete scheme. AMSS reports 7 failed decapsulations in 50,000 honest NSS-HQC-256 sessions (`1.4·10^-4`). An independent deterministic search found a failing submitted-library transcript at seed index 4201; `kem_dec` returns `-1` and its key differs from the encapsulated key, while adjacent seeds agree. The submitted `nss_hqc_dec` also returns `NSS_ERR_DECAP` when the re-encryption check fails (`nss_hqc_core.c:1020–1060`). These checks confirm the failure-rate discrepancy and an observable failure bit, but not key recovery.

Sun's follow-up reports a completed adaptive attack on the unmodified 256-bit reference implementation. Honest-form ciphertexts with chosen message, salt, and position-tagged error offset expose a weak secret-dependent failure signal. Accumulating about `1.3·10^8` decapsulations reportedly recovered both 117-position secret supports exactly; the reconstructed equivalent key then decrypted a fresh honest ciphertext. This would violate the claimed IND-CCA2 security within the call's `2^80` chosen-ciphertext budget, hence Critical. The per-position statistics and full key recovery are the reporter's results, not independently reproduced here, hence Probable. The 384/512 query estimates are extrapolations, and no analogous 128-bit recovery is claimed.

### Reproducing

```sh
python3 kem-26/reproduce_failure.py
```

The compact witness replays the pinned failing seed and two adjacent controls. The earlier bounded search examined 30,000 deterministically derived seeds on the archived NSS-HQC-256 library. This checks the failure oracle, not Sun's adaptive recovery; the forum post supplies the only full-run evidence presently available.

## kem-26-3: Ephemeral syndrome decoding misses the 256-, 384-, and 512-bit targets

Severity: Critical
Status: Confirmed
Layer: Design
Affected: NSS-HQC-256, NSS-HQC-384, and NSS-HQC-512 parameters
Discovery: Moderate
Exploitation: Approximately 2^226.51, 2^333.04, and 2^441.39 bit operations after the standard QC/DOOM discount
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-30

The specification estimates finite-size decoding security by extrapolating one
HQC-128 value as `1.0969 sqrt(n)` (§4.5.2, Equations 91–92). It then says that
reducing the ephemeral weights changes the exponent by less than 5, 7, and 9
bits (§4.4.5, Table 5) and claims that the 256-, 384-, and 512-bit sets meet
their respective targets (§4.5.3–4.5.4, Tables 7–8).

Direct finite-size Stern estimates contradict those claims:

| set | public SD instance from `u=r1+h*r2` | Stern time | memory | after `sqrt(n)` QC/DOOM discount | target |
|---|---:|---:|---:|---:|---:|
| NSS-HQC-256 | `[108986,54493,212]` | 234.38 | 46.20 | **226.51** | 256 |
| NSS-HQC-384 | `[245158,122579,318]` | 341.49 | 49.71 | **333.04** | 384 |
| NSS-HQC-512 | `[435802,217901,426]` | 450.26 | 52.20 | **441.39** | 512 |

All figures are base-two bit complexities from
`cryptographic-estimators==2.1.1`. The conclusion does not depend on the
quasi-cyclic discount: the raw Stern costs are already below all three claimed
levels. The analogous NSS-HQC-128 result is 154.43 raw and 147.01 after the
discount, so that set is not affected by this finding.

This is a shared-secret recovery attack, not only a smaller abstract decoding
number. Solving the first ciphertext component recovers the essentially unique
weight-`2w_r` pair `(r1,r2)`. The expected number of unrelated solutions is
below `2^-52000` even for the smallest affected set.

Compression does not prevent message recovery. For each five-bit repetition
group, the attacker knows `a=(s*r2) xor d` from the public key, recovered
`r2`, salt, and public dither. In the absence of `e`, the two possible code
bits produce distinct quantizer symbols: if `Q(a)=c`, complementing the group
gives `Q(a xor 1^5)=3-c`. Thus the transmitted symbol determines the code
bit. Each bit of `e` can corrupt at most one inferred RM coordinate. A wrong
RM symbol needs at least 32 such errors, so the three affected weights
`187,279,372` cause at most `5,8,11` bad outer symbols, below the respective
RS correction radii `19,26,33`. The public concatenated-code decoder therefore
recovers `m`, and the session key follows from the public derivation
`H_kappa(m || ct_full)`. This breaks the required KEM indistinguishability
below every affected target, hence Critical.

### Reproducing

Install the pinned estimator in an isolated environment and run:

```sh
python3 -m venv /tmp/ngcc-code-estimator
/tmp/ngcc-code-estimator/bin/pip install cryptographic-estimators==2.1.1
/tmp/ngcc-code-estimator/bin/python kem-26/reproduce_isd_estimate.py
```

The script prints the optimized Stern parameters, raw time and memory, the
QC/DOOM discount, the discounted result, and the expected number of unrelated
fixed-weight solutions.

## kem-26-4: A 256-bit decryption sub-seed caps NSS-HQC-384 and -512

Severity: Critical
Status: Confirmed
Layer: Design
Affected: NSS-HQC-384 and NSS-HQC-512 specification, reference, and optimized implementations
Discovery: Moderate
Exploitation: About 2^279.4 and 2^280.6 bit operations, respectively
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SZSEV56NMNPV7244JS57WKI27Z3MDZLP/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/a3f0a6adb6b695922247d4b771f4deb73777a619/nss-hqc-seedy-width)

Key generation splits SHA3-512 output into two 256-bit sub-seeds (Algorithm 1, physical p. 17), even when Table 3 selects a 384- or 512-bit `seed_sk`. Decryption needs only `y`, which is determined by `seed_y` (physical p. 20). The code agrees: `NSS_HQC_I_SEED_BYTES` is 32 and `derive_xy_seeds` copies two 32-byte halves (`nss_hqc_core.c:25,432–439`). This contradicts the 384/512-bit seed-search costs in Table 7 (physical p. 40).

An attacker enumerates `seed_y`, expands `y`, recognizes it through the public relation `wt(s+h*y)=w_sk`, and then decrypts. About `2^255` candidates on average, with sparse-product costs near `2^24.35` and `2^25.60`, give about `2^279.4` and `2^280.6` bit operations—below both claims. The witness rebuilds `y` and decrypts at full size, then demonstrates the public enumeration end to end in an 8-bit scale model with random-candidate controls. It does not run the full `2^256` search.

### Reproducing

```sh
./kem-26/reproduce_seed_y_width.sh
```

## kem-26-5: RS-decoder timing reportedly recovers an NSS-HQC-128 key

Severity: Critical
Status: Probable
Layer: Side-channel
Affected: NSS-HQC-128 reference decapsulation; the other three sets share the decoder loop but have not been attacked end to end
Discovery: Non-trivial
Exploitation: Sun reports recovery of all 73 secret-support positions with 912,733 chosen-ciphertext decapsulations; not independently replayed
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-06
Original source: [Sun's NSS-HQC decoder-timing post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XAJUOVQVF2JXLF2UOD4COZAIEVWJZYJB/)

The submitted `pke_decrypt` combines the received ciphertext with the secret vector `y` before decoding (`nss_hqc_core.c:793–898`). The Reed–Solomon decoder then tries decreasing error counts and returns on its first successful trial (`code_layer.c:490–529,864–931`). Thus the number of trials can depend on the secret and an attacker-chosen ciphertext. The specification nevertheless says that the implementation is designed for constant-time execution (§4.5.5, physical p. 41). Its examples omit the RS decoder, but the general claim covers the implementation.

Sun reports a measured 1.1% decapsulation-time separation on chosen degenerate ciphertexts and exact recovery of the 73-position secret support at the 128-bit tier after 912,733 decapsulations. The reconstructed equivalent key reportedly decrypted a fresh honest ciphertext. This is a reported end-to-end key recovery contradicting the submitted constant-time claim, hence Critical under the side-channel rule. The source path and variable trial count are independently checked below, but neither the secret-dependent timing distribution nor the full recovery has been replayed; the status is therefore Probable. Higher-tier query counts in the post are extrapolations, not demonstrated attacks. This finding concerns NSS-HQC's submitted decoder, not the separate NIST HQC implementation.

### Reproducing

```sh
sh kem-26/reproduce_rs_decoder_iterations.sh
```

The native component witness includes the frozen NSS-HQC-128 decoder, checks that clean and random received words take different numbers of trials, and verifies its trial-loop result against the submitted `rs_decode`. It does **not** reproduce a secret-key timing oracle or key recovery; those remain the reporter's observations.
