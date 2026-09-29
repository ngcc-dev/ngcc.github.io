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
