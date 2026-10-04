<!-- synchronized report: kem-30/report.md -->
Candidate: PolarLAC
Family: Lattice-based (module-LWE with polar-code decoding)
Archive: [PolarLAC.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/PolarLAC.zip) (SHA-256: `906be26ce8d27de335b691ff8490b2344b46d7519d88c799cba0242324e4882c`)

## kem-30-1: Re-encryption rejection sampling leaks the decrypted-message class

Severity: Critical
Status: Probable
Layer: Side-channel
Affected: The rejection sampler occurs in all 20 reference and optimized x86/ARM trees; practical recovery demonstrated on PolarLAC-Light reference
Discovery: Hard
Exploitation: Complete recovery of all 512 secret coefficients from physical decapsulation timings, followed by decryption of a fresh ciphertext
Credit: Zhenyu Xiong and Mingsheng Wang; practical recovery by Jian Weng, Chi Cheng, Haochen Dou, Qian Guo, Thomas Johansson, Yanbin Pan, Dachao Wang, and Tianrun Yu
Date: 2026-09-27
Follow-up source: [PolarLAC team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NUOASTPTGEHI4GSVCJKRJFHSIXOECO5T/)

Practical follow-up: [Weng et al.'s PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PKC56RYJY3CKBY4NLXIWOZMU7LI3FV5V/), [pinned recovery artifact](https://github.com/Yutianrun/polarlac-timing-attack/tree/424c88cf44fa4330fa56ad19d275306d5c85692f), and [the PolarLAC team's confirmation](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JPI7NMTEE2PZMSUYOVCYC7YFVCRZQJQC/)

Reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §§3.3 and 3.7–3.8](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

Decapsulation re-encrypts the decrypted message for its Fujisaki--Okamoto check. The derived seed enters `sample_screened_poly`, whose spectral rejection loop repeats until a bound is met (`pke.c:30–42`). Its total rejection count `R` is therefore a deterministic public function of the secret-derived decrypted message, and execution time reveals that count. The generic statement that polar coding supports constant-time implementation (physical p. 4) is not contradicted; the relevant claim is that this implementation keeps constant-time control flow (§8.4, physical p. 39). The leaking rejection loop is data-dependent control flow.

The first artifact measured adjacent `R` classes about 9,000–10,600 cycles apart, but its attempted algebraic use of that coarse class recovered 0/512 coefficients. A later physical attack uses differential timing directly. On PolarLAC-Light it made 17,010,803 differential comparisons, each based on seven target/reference pairs (about 238 million decapsulation calls), recovered all 512 secret coefficients in 66.1 minutes, and used the recovered key to decrypt a fresh ciphertext. A second recorded run again recovered 512/512 coefficients.

### Follow-up Analysis

The PolarLAC team first confirmed the rejection-count channel while noting the earlier negative recovery result. It subsequently acknowledged the practical timing attack. Complete key recovery contradicts the explicit control-flow claim and is Critical under the classification policy. We validated the pinned source and both recorded recovery transcripts but have not independently rerun the 66-minute physical acquisition, so the status is Probable.

Constant-time fix (moderate): use fixed-work, message-independent sampling in the re-encryption path. The complete decapsulation, including reconstruction of its coins, must have a trace independent of the decrypted message and long-term key. This gives a Medium remediation floor; the demonstrated recovery and contradicted control-flow claim determine the higher Critical severity.

### Proposed fixes

The team's response proposes removing data-dependent rejection sampling. This records the proposal without assessing it.

### Reproducing

```sh
sh kem-30/reproduce_full_timing_recovery.sh
```

The wrapper fetches and hash-checks the pinned artifact, builds it, and validates both recorded complete-recovery runs and their fresh-ciphertext check. Set `NGCC_SLOW=1` to repeat the roughly 66-minute physical experiment; timing results depend on the host.

## kem-30-2: Secret-indexed LLR tables expose PolarLAC decoding through the cache

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference x86 and optimized x86/ARM implementations, all five parameter sets and both ARM hash families
Discovery: Trivial
Exploitation: Secret-dependent cache addresses in decapsulation; no key-recovery experiment supplied
Credit: Yamin Liu and Tianyuan Xie
Date: 2026-10-04
Original source: [PolarLAC team's PKC Forum acknowledgment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TEJHQONRU25BANZ2F24Q4CC2VRKEP4LH/)

PolarLAC computes each decoder log-likelihood ratio as `llr_table[centered + RATIO - 1]`, where `centered` comes directly from a decrypted coefficient (`poly.c:359–369` in the reference PolarLAC-512 tree). The table address therefore depends on secret-key and ciphertext data during decapsulation. The same lookup occurs in all 20 submitted `poly.c` copies.

The team confirms the cache leakage. No measured cache trace or candidate-specific recovery is public.

Constant-time fix (moderate, hence Medium): replace each 256-entry secret-indexed lookup with an oblivious lookup or an arithmetic LLR computation. Because this operation is repeated for every decoded coefficient, it is a material rewrite or slowdown rather than a small local mask.

### Proposed fixes

The team's response proposes replacing the lookup with an implementation having no secret-dependent memory access. This records the proposal without assessing it.

### Reproducing

```sh
python3 kem-30/reproduce_llr_cache_lookup.py
```
