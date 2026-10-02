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

## sign-34-4: Wrong Delta2 exponent causes excessive signing rejection

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: YuanYang.DSA-512 reference implementation
Discovery: Trivial
Exploitation: Increased signing retries; no key recovery, forgery, or output-distribution failure demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's YuanYang.DSA analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/)

Both YuanYang.DSA-512 implementations encode `fpr_yuanyang_inv_2sqrsigma_sig` as `3701747757852`, or approximately `0.42084` in Q20.43. For `sigma_sig = 69.76`, `1/(2 sigma_sig^2)` is approximately `0.000102744`, raw value `0x35de15c3`. The reference implementation applies the larger constant directly (`sign.c:325`), making its exponent 4096 times too large. The optimized implementation compensates by shifting the product right by 12 bits (`sign.c:311`) and is not affected.

In the reporters' isolated reference-code comparison, correcting this factor lowers Delta2 rejection from about 10.6% to 1.4% per completed signature. Other sampler corrections change the input distribution and its final rejection rate, so this comparison is not a general performance prediction. The confirmed consequence is an unnecessary retry cost in the archived 512 reference implementation; no cryptographic claim violation is demonstrated.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FMDKNMFRD7Q74TF5U5ZEA2P2XA3YII7S/) proposes dividing the reference Delta2 exponent constant by `2^12` together with correcting the perturbation covariance. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 sign-34/reproduce_sampler_constants.py
```

`sign-34/reproduce_sampler_mean.sh` also prints the public package's pinned 400,000-signature isolated Delta2 comparison after its fresh sampler run.
