<!-- synchronized report: kem-35/report.md -->
Candidate: Scloud+
Family: Lattice-based (unstructured LWE with Barnes–Wall decoding)
Archive: [Scloud+.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Scloud%2B.zip) (SHA-256: `050aad7293ec90fafd9070e82877eedc81caf0aaaca932c995619a3f35429876`)

## kem-35-1: Re-encryption rejection sampling leaks the decrypted-message class

Severity: High
Status: Confirmed
Layer: Side-channel
Affected: Reference and optimized Scloud+-256, -384, and -512; all AES, SHAKE, and SM3 families
Discovery: Moderate
Exploitation: Physical timing recovers 12,743 of 13,024 secret coefficients (97.8%) in 26.4 minutes; completion to an exact key is not demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4CQU6FWGGX4KK7XBHMBM6535CHEYX7HF/) and [pinned public artifact](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/709d5ec64239206effb2667ca853ddcef3c060b4/scloudplus-reencryption-timing)

Practical follow-up: [Weng et al.'s PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PKC56RYJY3CKBY4NLXIWOZMU7LI3FV5V/) and [pinned recovery artifact](https://github.com/Yutianrun/scloudplus-timing-sca/tree/5fa4a879ba95d36b3bd1e4ff5ad553c7c9a64ef3)

Decapsulation re-encrypts the decrypted message `m'` for its Fujisaki--Okamoto check (`common/kem.c:96–113`). The resulting seed enters the BD6 or BD12 rejection sampler, whose number of accepted candidates, refills, and XOF squeezes depends on that secret-derived seed (`common/sample.c:325–374,401–446`). The accepted-bit compaction also writes through the secret-derived index `count` (`common/sample.c:345–364,421–436`; `avx2/sample_avx2.c:139,161,206–226`). Both the reference and AVX2 implementations therefore have a decrypted-message-dependent execution trace. Scloud+-128 and -192 use non-rejection samplers and are controls.

Instrumentation over 5,000 honest Scloud+-256 decapsulations measured 296--301 sampler batches and 53--54 XOF squeezes. The original post reports a 6,209-cycle sampler-only gap with Welch's `t = 53.2`; independent reruns measured significant but host-dependent gaps around 6,000--6,700 cycles. These are microbenchmarks of the sampler, not whole decapsulation: the post estimates only a 0.1--0.3% end-to-end effect.

The first post stopped at a plaintext-checking-style timing bit. The practical follow-up applies differential physical measurements to Scloud+-L256's AVX2/AES-NI implementation. With 400 baseline decapsulations per coefficient it recovers 12,743 of 13,024 coefficients (97.8%) in 325.2 seconds of offline search plus 1,260.2 seconds of physical recovery. The published run supplies neither confidence scores nor a second-pass method for the remaining 281 errors, and it does not demonstrate a working decapsulation key. High follows from the candidate-specific near-recovery path; it does not assume that completing the key is easy. The submission makes no constant-time claim, so the result is not Critical under the classification policy.

### Constant-time fix (moderate; Medium remediation floor)

Make candidate generation and compaction consume fixed work: process a fixed upper-bound number of candidates and select accepted values obliviously. This is a substantive sampler rewrite rather than a local mask, but it uses standard fixed-work and oblivious-compaction techniques; the expected cost is moderate and has not been measured here.

### Proposed fixes

The original post proposes processing a fixed upper-bound number of candidates with constant-time compaction, or replacing the rejection sampler with a non-rejection construction based on fixed-point comparison against `1/6` or `1/12`. This section records those proposals without evaluating them.

### Reproducing

```sh
sh kem-35/reproduce_reencryption_timing.sh
```

The earlier wrapper fetches the pinned artifact and runs its deterministic squeeze-count and timing experiments against the archived optimized implementation. It requires network access, an x86-64 processor with AVX2 and AES-NI, and `taskset` from util-linux. Absolute cycle counts depend on host scheduling; the deterministic squeeze-count result does not.

To validate the later recovery evidence:

```sh
sh kem-35/reproduce_partial_key_recovery.sh
```

It fetches and hash-checks the pinned artifact and validates its recorded 12,743/13,024 recovery. Set `NGCC_SLOW=1` to rerun the roughly 26-minute AVX2/AES-NI experiment.
