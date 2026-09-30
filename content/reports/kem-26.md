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

## kem-26-2: NSS-HQC-256 fails honest decapsulation near 10^-4

Severity: Medium
Status: Confirmed
Layer: Design
Affected: NSS-HQC-256 parameters, DFR analysis, and submitted reference implementation
Discovery: Moderate
Exploitation: Honest-session mismatch; potential failure-oracle implications are not developed into key recovery
Credit: Information Security Center, Academy of Mathematics and Systems Science, Chinese Academy of Sciences
Date: 2026-09-30
Original source: [AMSS PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DGP2J3ZUZJYNC4COYWQQ77L42OOFNCP7/)

The specification selects every parameter set under `DFR_NSS < 2^-128` (§3.6) and uses that bound in its IND-CCA2 loss. Its calculation replaces the five-bit compressor's correlated errors with a binary-symmetric-channel proxy. Equation (68) is also labelled an upper bound although it counts only error patterns matching nonzero RM codewords; the forum gives `7.53·10^-45` at crossover probability `1/4`, while one omitted failure event alone has probability at least `4.59·10^-6`.

The mismatch is observable in the complete scheme. AMSS reports 7 failed decapsulations in 50,000 honest NSS-HQC-256 sessions (`1.4·10^-4`). An independent deterministic search found a failing submitted-library transcript at seed index 4201; `kem_dec` returns `-1` and its key differs from the encapsulated key, while adjacent seeds agree. This confirms that the advertised DFR analysis is not conservative for the shipped parameters. No reaction attack or secret recovery is demonstrated.

### Reproducing

```sh
python3 kem-26/reproduce_failure.py
```

The compact witness replays the pinned failing seed and two adjacent controls. The earlier bounded search examined 30,000 deterministically derived seeds on the archived NSS-HQC-256 library.

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
