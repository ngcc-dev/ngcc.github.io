<!-- synchronized report: kem-30/report.md -->
Candidate: PolarLAC
Family: Lattice-based (module-LWE with polar-code decoding)
Archive: [PolarLAC.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/PolarLAC.zip) (SHA-256: `906be26ce8d27de335b691ff8490b2344b46d7519d88c799cba0242324e4882c`)

## kem-30-1: Re-encryption rejection sampling leaks the decrypted-message class

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: PolarLAC-Light reference implementation; shared sampler pattern appears in the other reference sets
Discovery: Hard
Exploitation: Measured timing classification of a decrypted-message-dependent rejection count; key recovery and IND-CCA break explicitly not demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang
Date: 2026-09-27
Follow-up source: [PolarLAC team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NUOASTPTGEHI4GSVCJKRJFHSIXOECO5T/)

Reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §§3.3 and 3.7–3.8](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

Decapsulation re-encrypts the decrypted message for its Fujisaki--Okamoto check. The derived seed enters `sample_screened_poly`, whose spectral rejection loop repeats until a bound is met (`pke.c:30–42`). Its total rejection count `R` is therefore a deterministic public function of the secret-derived decrypted message, and execution time reveals that count. This contradicts the specification's claims that the polar-code implementation has constant-time control flow and intrinsically supports constant-time implementation.

On PolarLAC-Light, the artifact measures adjacent `R` classes about 9,000–10,600 cycles apart and classifies them with low error after repeated measurements. The timing channel is real. The paper also carefully reports the negative result: the chosen-ciphertext message-flip predicate needed by its algebraic recovery has 68–99% error through this timing channel, and a genuine-timing run recovers 0/512 coefficients. This report therefore claims secret-dependent timing leakage, not key recovery or an IND-CCA break.

### Follow-up Analysis

The PolarLAC team confirms the measurable rejection-count timing leakage and agrees that it does not presently give the plaintext predicate required by the reported key-recovery method. It notes that the re-encryption coins are derived from `Hash(m || pk)`, making the observed class a pseudorandom function of the decrypted message rather than a direct structured relation to its bits. This is consistent with the report's Medium scope and does not change its classification.

Use fixed-work, message-independent sampling in the re-encryption path. The complete decapsulation, including reconstruction of its coins, must have a trace independent of the decrypted message and long-term key.

### Reproducing

```sh
sh kem-30/reproduce_timing_leak.sh
```

The wrapper fetches the [pinned artifact](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/e724a12a834bfc063dc0d2959d864842f269eb1e/polarlac-timing-leak), builds its timing harnesses against the unmodified PolarLAC-Light sources here, and runs both the measured-channel experiment and the negative exploitability controls. Results depend on host scheduling; use `CORE=<idle CPU>` to select a pinned core.
