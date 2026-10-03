<!-- synchronized report: kem-16/report.md -->
Candidate: HARE
Family: Code-based (quasi-cyclic)
Archive: [HARE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/HARE.zip) (SHA-256: `718bb70eee268550fcef2a82e8eb9879c51ecfdbaefd6bfe2157e7639ffc8557`)

## kem-16-1: Headline DFR values lack a reproducible HARE calculation

Severity: Medium
Status: Proof gap
Layer: Design
Affected: HARE-128 and HARE-256 specification (HARE-2 and HARE-5)
Discovery: Moderate
Exploitation: Proof gap; no excessive failure rate or practical attack demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, Institute of Information Engineering, Chinese Academy of Sciences, with Anthropic Claude Opus 5.5 assistance
Date: 2026-09-29
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/I3GOGQ7HXLFUKK5E3I562VHM3VAGNSJ6/)

HARE's Table 2 claims decryption-failure probabilities below `2^-130` and `2^-258` for its submitted 128- and 256-bit sets. These two claims use the refined dependent-coordinate Model 2 in §6. The cited [Bitzer et al. artifact](https://gitlab.com/HQCCiphertextCompression/hqc-with-ciphertext-compression) implements Model 2 for HQC, but the archived HARE package provides no adaptation that produces HARE's convolution distribution and combined error/erasure failure count.

An independent implementation of the simpler Model 1 from §§5.1–5.3 gives `2^-121.4485` and `2^-239.2123`. These are short of Table 2's advertised bounds by about 8.6 and 18.8 bits, and short of the 128- and 256-bit security levels by about 6.6 and 16.8 bits. As a control, the same calculation reproduces Table 2's Model-1 figures for HARE-384 and HARE-512: `2^-384.9304` and `2^-519.4516`.

The code package's `PARAMETER_MANIFEST.tsv` also labels HARE-256's `<2^-258` value as “Model-1,” contradicting both the PDF's Model-2 label and the direct Model-1 recomputation. This appears to be a metadata error rather than evidence for either bound.

This does not show that HARE's true failure probability exceeds its target: Model 1 is a conservative upper bound, and Model 2 may be correct. It shows that the headline sets depend on a tighter candidate-specific numerical calculation for which no checkable artifact was submitted. Publishing that implementation and its inputs, or selecting parameters that meet the target under the conservative calculation, would close the gap.

### Reproducing

Run the standard-library implementation of specification §§5.1–5.3:

```sh
python3 kem-16/reproduce_model1_dfr.py
```

It recomputes all four values above and checks the two specification-published Model-1 controls before printing `CONFIRMED`.

## kem-16-2: Same-key multi-instance decoding misses three HARE targets

Severity: Critical
Status: Confirmed
Layer: Design
Affected: HARE-256, HARE-384 and HARE-512 (HARE-5, HARE-7 and HARE-9)
Discovery: Moderate
Exploitation: About 2^255.44 work after 2^72 ciphertexts, 2^383.18 after 2^64, or 2^511.70 after 2^75
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-03
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5M6UUTE7ZUSDW7XRVMLAMZGNU55A4IYT/)

Additional reference: [May and Sá Diogo, ePrint 2026/517](https://eprint.iacr.org/2026/517)

Each HARE ciphertext exposes the uncompressed syndrome `u = r1 + h*r2`, where `h` is fixed by the public key and both errors have weight `wr` (Algorithm 4, physical p. 10; `_shared/hare_core/ref/hqc.c`). From `Q` ciphertexts and their public cyclic shifts, an attacker obtains `nQ` targets for one same-code Decoding-One-Out-of-Many search. Recovering one error pair decodes that ciphertext's message and derives its session key.

The pinned heuristic estimator gives the following first below-target points: HARE-256 at `Q=2^72`, time `2^255.440` and memory `2^103.356`; HARE-384 at `Q=2^64`, time `2^383.175` and memory `2^97.358`; HARE-512 at `Q=2^75`, time `2^511.699` and memory `2^109.820`. HARE-128 remains above its target at the `2^80` evaluation ceiling.

Further extension to Xiong and Wang's analysis: using the conservative ordinary code dimension `n`, rather than `n-2`, preserves all three crossings. Checking every observation exponent also moves HARE-512's first crossing from the reported grid point `2^76` to `2^75`; the preceding costs are `2^256.300`, `2^384.046` and `2^512.163`.

These passive attacks need no decapsulation oracle and stay within the `2^80` evaluation ceiling, but their first-crossing margins are only 0.56, 0.82 and 0.30 bits and the estimates require `2^97`–`2^110` bits of memory. The crossings use one pinned heuristic DS-DOOM estimator; alternate operation-count or memory-cost conventions could close these sub-bit margins. We reproduced the estimator calculations and the public ciphertext-to-session-key mapping; we did not execute the full decoding searches.

### Reproducing

```sh
python3 kem-16/reproduce_multi_instance.py
make -C kem-16 reproduce-multi-instance
```

The first command requires NumPy and SciPy, hash-pins the estimator and checks each target crossing; set `NGCC_ESTIMATOR_PYTHON` to a suitable Python executable if they are not available to `python3`. The native witness links the submitted code and validates syndrome formation, rotations, decoded-message recovery, session-key recovery and a wrong-output control on all four shipped sets.
