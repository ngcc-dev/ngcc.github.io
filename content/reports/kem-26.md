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
