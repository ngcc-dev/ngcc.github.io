<!-- synchronized report: kem-35/report.md -->
Candidate: Scloud+
Family: Lattice-based (unstructured LWE with Barnes–Wall decoding)
Archive: [Scloud+.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Scloud%2B.zip) (SHA-256: `050aad7293ec90fafd9070e82877eedc81caf0aaaca932c995619a3f35429876`)

## kem-35-1: Re-encryption rejection sampling leaks the decrypted-message class

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference and optimized Scloud+-256, -384, and -512; all AES, SHAKE, and SM3 families
Discovery: Hard
Exploitation: Repeatable decrypted-message-dependent timing; key recovery and IND-CCA break not demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/4CQU6FWGGX4KK7XBHMBM6535CHEYX7HF/) and [pinned public artifact](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/709d5ec64239206effb2667ca853ddcef3c060b4/scloudplus-reencryption-timing)

Decapsulation re-encrypts the decrypted message `m'` for its Fujisaki--Okamoto check (`common/kem.c:96–113`). The resulting seed enters the BD6 or BD12 rejection sampler, whose number of accepted candidates, refills, and XOF squeezes depends on that secret-derived seed (`common/sample.c:325–374,401–446`). The accepted-bit compaction also writes through the secret-derived index `count` (`common/sample.c:345–364,421–436`; `avx2/sample_avx2.c:139,161,206–226`). Both the reference and AVX2 implementations therefore have a decrypted-message-dependent execution trace. Scloud+-128 and -192 use non-rejection samplers and are controls.

Instrumentation over 5,000 honest Scloud+-256 decapsulations measured 296--301 sampler batches and 53--54 XOF squeezes. The original post reports a 6,209-cycle sampler-only gap with Welch's `t = 53.2`; independent reruns measured significant but host-dependent gaps around 6,000--6,700 cycles. These are microbenchmarks of the sampler, not whole decapsulation: the post estimates only a 0.1--0.3% end-to-end effect.

The squeeze class is a public function of a guessed `m'` and the public key. Timing therefore supplies a plaintext-checking-style bit, but the post estimates roughly `10^3` decapsulations per recovered bit and gives no Scloud+-specific key-recovery procedure. No null-control experiment is included in the artifact, and no key recovery or IND-CCA break has been demonstrated.

### Constant-time fix (moderate, hence Medium)

Make candidate generation and compaction consume fixed work: process a fixed upper-bound number of candidates and select accepted values obliviously. This is a substantive sampler rewrite rather than a local mask, but it uses standard fixed-work and oblivious-compaction techniques; the expected cost is moderate and has not been measured here.

### Proposed fixes

The original post proposes processing a fixed upper-bound number of candidates with constant-time compaction, or replacing the rejection sampler with a non-rejection construction based on fixed-point comparison against `1/6` or `1/12`. This section records those proposals without evaluating them.

### Reproducing

```sh
sh kem-35/reproduce_reencryption_timing.sh
```

The wrapper fetches the pinned artifact and runs its deterministic squeeze-count and timing experiments against the archived optimized implementation. Absolute cycle counts depend on host scheduling; the deterministic squeeze-count result does not.
