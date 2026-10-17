<!-- synchronized report: sign-34/report.md -->
Candidate: YuanYang.DSA
Family: Lattice-based (NTRU hash-and-sign)
Archive: [YuanYang.DSA.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/YuanYang.DSA.zip) (SHA-256: `1eb45f24ad8f7ff25db923479c6500f273aee8b2470d76339030fed8d96b5b31`)

## sign-34-1: Wrong perturbation covariance leaks secret-basis information

Severity: High
Status: Confirmed
Layer: Implementation
Affected: YuanYang.DSA-512, -1024, and -2048 reference and optimized implementations
Discovery: Non-trivial
Exploitation: Key-dependent transcript distinguisher from a few thousand signatures; complete key recovery not demonstrated
Credit: Kris Kwiatkowski <contact@amongbytes.com>
Date: 2026-09-22
Original source: [ngcc-harness PR #2](https://github.com/ngcc-dev/ngcc-harness/pull/2), superseded by [PR #3](https://github.com/ngcc-dev/ngcc-harness/pull/3)
Follow-up source: [Xiong and Wang's YuanYang.DSA analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/)

The specification represents the NTRU basis vectors as columns and requires perturbation covariance `Sigma_p = sigma^2 I - B_hat B_hat^*`. The implementation's `sigma_p_set_slot()` instead subtracts `B_hat^* B_hat`, the Gram matrix of those basis vectors. Since the two matrix products differ for this non-normal basis, the intended cancellation fails and leaves secret-dependent variance and cross-covariance in every signature.

For each Fourier slot, the diagonal leakage predicts `Var(s1)=sigma_eff^2-|g|^2+|F_hat|^2` and the opposite deviation in `Var(s2)`. The off-diagonal covariance combines with that difference to expose an approximation to the slotwise ratio `f/g`. The public-data reproducer decodes only published signature bytes and never reads the secret key. On an independently generated YuanYang-512 key, 4,000 signatures produced a 7.4-sigma dispersion and a 2.23-fold slot-variance spread; a spherical control produced 1.0 sigma and a 1.08-fold spread. The faulty source is byte-identical across all three parameter sets.

This confirms substantial key-dependent leakage and invalidates the claimed spherical-transcript simulation. It does not yet recover `(f,g)` or forge a signature: the proposed final rank-one module-lattice recovery has not been implemented, and the observed ratio estimate retains a systematic error floor. The implementation must subtract `B_hat B_hat^*`, and the repaired sampler must be revalidated statistically.

### Follow-up Analysis

Zhenyu Xiong and Mingsheng Wang's [2026-09-30 PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/) independently identifies the transposed covariance product and shows that it combines with the separate YuanYang.DSA-512 wide-sampler defect described below. The follow-up strengthens the public-signature leakage evidence, but does not complete the key-recovery step for this covariance defect by itself.

### Reproducing

```sh
make -C sign-34 exploit
sign-34/reproduce_transcript_leak sign-34/lib/libyuanyang-512.so 4000
```

The same run also prints a separate public-key packing witness. Its
4,000-signature count is needed by this statistical test, not by the encoding
check.

## sign-34-2: Non-injective public-key packing creates key aliases

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: YuanYang.DSA-512, -1024, and -2048 public-key encodings
Discovery: Moderate
Exploitation: Trivial transformation of an aliasable packed block
Credit: Kris Kwiatkowski <contact@amongbytes.com>
Date: 2026-09-22
Original source: [ngcc-harness PR #2](https://github.com/ngcc-dev/ngcc-harness/pull/2), superseded by [PR #3](https://github.com/ngcc-dev/ngcc-harness/pull/3)

The implementation packs four coefficients as a fixed-width radix-`q` integer but never rejects integers at least `q^4`. Decoding uses repeated reduction modulo `q`, so adding `q^4` to any block with sufficient encoding slack changes the byte string while recovering exactly the same four coefficients.

For the 512, 1024, and 2048 sets, the block widths are 46, 49, and 52 bits and unused codeword fractions are approximately 25.70%, 28.38%, and 22.71%. The boundary words `0` and `q^4` decode to the same coefficient tuple in every set. The runtime witness alters an actual YuanYang-512 public key and confirms that its bytes differ while the same signature verifies under both encodings.

This is not an EUF-CMA forgery, because the mathematical public key is unchanged. It breaks canonical key identity and can defeat systems that fingerprint, pin, compare, or hash serialized public keys. Decoding must reject each packed block unless it is strictly below `q^4`, or re-encode and compare the complete public-key byte string.

### Reproducing

```sh
make -C sign-34 exploit
sign-34/reproduce_transcript_leak sign-34/lib/libyuanyang-512.so 4000
```

## sign-34-3: Wrong wide-sampler constant leaks secret-basis information through signature means

Severity: High
Status: Confirmed
Layer: Implementation
Affected: YuanYang.DSA-512 reference and optimized implementations
Discovery: Non-trivial
Exploitation: Strong public-signature leakage with a candidate-specific key-recovery route; complete recovery is simulated, not executed
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's YuanYang.DSA analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/)

The YuanYang.DSA-512 RCDT and specification use a wide integer Gaussian of standard deviation `4 eta = 4.104`. Both submitted implementations instead set the fixed-point rejection exponent to `1/(2(16 eta)^2)`. The submitted Q20.43 constant is `0x3ccc24a85`, or `0.00185539045`; the constant for `4 eta` is `0x3ccc24a84f`, or `0.02968624724`. The 1024- and 2048-dimensional sets use the correct scale and are unaffected by this finding.

The erroneous rejection step leaves the one-dimensional sampler with mean about `0.458` rather than zero. That bias passes through the secret Gram root and gives the public signature coefficients a large, key-dependent mean. At 400,000 signatures per test key, the reporters' own-key regressions have slopes `0.102 +/- 0.011` and `0.113 +/- 0.010`, close to the predicted `0.458/4`, while cross-key controls remain near zero. Correcting only the wide-sampler constant removes the mean signal.

The recovered quantity approaches the secret autocorrelation `f fbar + g gbar`. Fouque, Kirchner, Tibouchi, Wallet, and Yu, [ePrint 2019/1180](https://eprint.iacr.org/2019/1180), give a polynomial-time full-key recovery once that autocorrelation is exact. The reporters estimate coefficient-wise recovery at roughly `2^35` signatures, but that scale is a simulation corresponding to about 400 core-days of victim signing; they did not execute the complete recovery. This is therefore High rather than Critical.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/) proposes setting the exponent constant to `0x3ccc24a84f`, regenerating `yuanyang_large_zero_berexp[]` for `4 eta`, and adding signature mean and variance self-tests to the KAT suite. This section records the proposal without evaluating it.

### Reproducing

The local certificate checks both submitted source trees and the two fixed-point factors:

```sh
python3 sign-34/reproduce_sampler_constants.py
```

The pinned public experiment recompiles isolated copies, compares the submitted and corrected samplers, and runs the public-signature mean test. It needs Python with NumPy; 20,000 signatures show the mean, while 400,000 are needed for the reported approximately ten-sigma secret regression.

```sh
PYTHON_BIN=python3 sh sign-34/reproduce_sampler_mean.sh 20000
```

## sign-34-4: The Delta2 rejection test makes returned signatures depend on a secret quadratic form

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: YuanYang.DSA-512 and -2048 reference implementations (executed); the same clamp and sign reversal in the -1024 reference and all three optimized implementations (source)
Discovery: Moderate
Exploitation: Increased signing retries and a measured secret-dependent selection of returned signatures, using the signer's own quadratic form; no public estimator, key recovery or forgery demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance; output-distribution extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's YuanYang.DSA analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/)

Both YuanYang.DSA-512 implementations encode `fpr_yuanyang_inv_2sqrsigma_sig` as `3701747757852`, or approximately `0.42084` in Q20.43. For `sigma_sig = 69.76`, `1/(2 sigma_sig^2)` is approximately `0.000102744`, raw value `0x35de15c3`. The reference implementation applies the larger constant directly (`sign.c:325`), making its exponent 4096 times too large. The optimized implementation compensates for this constant by shifting the product right by 12 bits (`sign.c:311`).

In the reporters' isolated reference-code comparison, correcting this factor lowers Delta2 rejection from about 10.6% to 1.4% per completed signature. Other sampler corrections change the input distribution and its final rejection rate, so this comparison is not a general performance prediction.

Reclassified on 2026-10-17 from Low to Medium. This record previously stated that the optimized implementation is not affected and that no output-distribution failure was demonstrated. Both statements were wrong.

The second rejection step of Sample must remove the covariance error left by the rounded Gram root. Equation (4) in Section 4.2.2 (physical p. 16) and Algorithm 10, line 12 (p. 18) set `Delta2 = (1/C) exp(+x^T T x / (2 sigma_sig^2))` with `x = z - c` and `T ~ Sigma_delta/sigma^2`. Since `Sigma_delta` is indefinite, the factor must be applied for both signs of the quadratic form. The submitted code departs from this in three ways. `yuanyang_sign_ntt_delta2_weight()` returns zero whenever the dot product is not positive (`if (dot_cmp <= 0) ... return fpr_zero`, reference `sign_ntt.c:1254–1270`, `:1231–1247` and `:1209–1225` for 512, 1024 and 2048; optimized `:1221–1237`, `:1210–1226` and `:1197–1213`). `delta2_probability_ntt()` then returns `fpr_expm_p62(exponent) * weak_inv_C` (reference `sign.c:325–327`), which is `exp(-w)/C`: the sign of the exponent is reversed. Finally, the weight is scaled by `2^(LOGD-1) = d/2` (`sign_ntt.c:1274`, and the corresponding lines in every tree). Combined with each set's exponent constant, the implemented exponent is `2^20` times the specified one in the 512 reference implementation, `2^8` times in the 512 optimized implementation, and `1/8` times in the 1024 trees. In the 2048 reference implementation it is not a fixed multiple: 15% of evaluations exceed 1, and those below 1 average about `10^4` times the specified value.

The implemented test therefore accepts every candidate with `x^T G x <= 0` with probability `1/C`, and rejects candidates with `x^T G x > 0` far more often than the specification allows, where `G = Sigma_delta/sigma^2` is secret. Because `x` is the signature vector up to sign, acceptance selects on a secret quadratic form of the returned signature. On instrumented copies of the reference trees, whose first signature is byte-identical to the prebuilt libraries, the implemented acceptance probability was 0.666 for `q > 0` against 0.985 for `q < 0` at YuanYang.DSA-512 (2,000 signatures), and 0.668 against 0.969 at -2048 (1,000 signatures). The specification gives about 0.985 and 0.969 for both signs. The share of returned signatures with `q < 0` rose from 0.746 among candidates to 0.808 (z = 6.4) at 512, and from 0.685 to 0.761 (z = 5.2) at 2048. The same statistics under the form of an unrelated key stayed flat: acceptance 0.903 against 0.906 and 0.881 against 0.852, with returned shares unchanged (z = -0.6 and -0.4). Every honest signature verified.

The output of Sample is therefore not close to the target Gaussian, and the Rényi term `R_a(Sample || D)` of Theorem 5.2 is not near 1 per query. The losses printed in Table 4 (p. 30) for `C_s ~ 2^80` repetitions do not cover the submitted signer. At 1024 and in the 512 optimized implementation the specified correction, whose exponent is of order `10^-6` per signature, is dropped for negative forms and mis-scaled for positive ones. That residue is again far above what the bound tolerates over `2^80` queries, but it is too small to measure in a short run.

The leak was measured as a key-dependent distinguisher using the secret `G`. A public-only estimator of `Sigma_delta` from signatures was not built, and no route from `Sigma_delta` (the rounding residue of the Gram root) to `(f, g)` is known. The optimized trees were analysed from source and not executed, and the source of the 2048 exponent scale was measured but not traced to one line.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/) proposes dividing the reference Delta2 exponent constant by `2^12` together with correcting the perturbation covariance. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 sign-34/reproduce_sampler_constants.py
sh sign-34/reproduce_delta2_selection.sh
```

`sign-34/reproduce_sampler_mean.sh` also prints the public package's pinned 400,000-signature isolated Delta2 comparison after its fresh sampler run.

The second script checks the clamp and `exp(-w)` lines in all six trees, builds instrumented copies of the three reference trees in a temporary directory, checks each copy's first signature against `sign-34/lib/libyuanyang-*.so`, and signs 2,000, 100 and 1,000 messages (about 75 seconds). Its controls are honest verification, rejection of mutated signatures and changed messages, and the flat unrelated-key form; `NGCC_LONG=1` signs 6,000, 1,000 and 3,000 messages.

## sign-34-5: An unsalted 256-bit prehash permits signature transfer at the higher levels

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: YuanYang.DSA-1024 and -2048 reference and optimized implementations
Discovery: Trivial
Exploitation: About 2^128.24 SM3 evaluations at 50% collision success, one signing query, then a fresh-message forgery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

The specification hashes a fresh salt before the message and public key (§4.2.1). The submitted YuanYang.DSA-1024 and -2048 reference and optimized trees instead compute `seed = SM3(M || h)` *before* choosing the signature salt, and then derive the challenge only from `salt || seed` (for example `Implementations/Reference_Implementation/yuanyang-2048/common.c:33–54`, `sign.c:583–615`, `vrfy.c:116–127`, with matching paths in the other trees). Here `h` is the fixed public key. Two equal-length messages colliding in the 256-bit SM3 output therefore yield the same challenge under **any** salt. Obtain one signature on either message and reuse it on the other; verification has no way to distinguish them.

A birthday search reaches 50% collision probability after about 2^128.24 evaluations, below the 256- and 512-bit claims of the 1024- and 2048-dimensional sets. The 512-dimensional set targets 128 bits and is excluded. This is an analytic attack against the submitted message-binding order, not a full-size collision search carried out here; the source and hash width determine the bound even if the later challenge XOF is ideal.

### Reproducing

```sh
python3 sign-34/reproduce_prehash_ceiling.py
```

The certificate checks both implementation families and the salt-after-prehash data flow, then computes the birthday bound.

## sign-34-6: The 1024 and 2048 sets reuse the 512 set's Delta1 normalisation constant

Severity: Medium
Status: Proof gap
Layer: Implementation
Affected: YuanYang.DSA-1024 and -2048 reference and optimized implementations
Discovery: Moderate
Exploitation: Source certificate of the wrong constant; the statistical effect is not measured, and no key recovery or forgery is demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

The first rejection step of Sample, Delta1, removes the centre-dependent normalisation that RingSamp introduces. Algorithms 12 and 13 (Section 4.2.2, physical p. 19) multiply by `1 + (2cos(2 pi c) - 2)/(r^-1 + r + 2)` with `r = exp(-2 pi^2 eta^2)`, and Table 3 (p. 26) sets `eta = 1.026`, `0.974` and `0.928` for the three sets. The specification calls this "the correction that permits the hybrid sampler to operate under the weak-smoothness condition" (p. 16). `theta_div_q62()` (reference `sign.c:101–118`) evaluates `1 + (cos - 1) * theta_den[0]`, so `theta_den[0]` must equal `2/(r^-1 + r + 2)` for the set's own `eta`.

Every tree stores `YY_FPR_Q62_RAW(0x0000000207f55527)` (reference `fpr.h:557–558` for 512 and `fpr.h:560–561` for 1024 and 2048; optimized `fpr.h:610–611`, `609–610` and `609–610`). That is exactly the value for `eta = 1.026`. The 1024 and 2048 sets require `0xfd29fe7a9` and `0x58fc3fbbe8`, so they apply only 12.8% and 2.3% of the specified correction. The same `fpr.h` files encode the RingSamp width `inv_2sqreta` with the correct per-set `eta`, and the 512 constant is exact, which places the error in this one copied constant.

The sampled vectors therefore keep an uncorrected centre-dependent factor of up to about `5e-8` (1024) and `3e-7` (2048) per coordinate, of the same order as the smoothness slack `epsilon = 2^-26` and `2^-23.5` in Table 3. Theorem 5.2 and Table 4 (p. 30) bound the sampler's Rényi divergence with orders `a_p = 1908.6` and `168.7` over `C_s ~ 2^80` samples on the assumption that this factor has been removed. The proof for these two sets no longer covers the implemented sampler, and the query range that remains covered has not been computed. The per-signature effect is far too small to measure in a short experiment.

### Reproducing

```sh
python3 sign-34/certify_theta_constant.py
```

The certificate parses all six `fpr.h` and `sign.c` files, recomputes the required constant from Table 3's `eta`, and cross-checks `eta` against each tree's own RingSamp constant and `2r` against Table 3's `epsilon`. The 512 trees serve as the matching control; it runs in well under a second.
