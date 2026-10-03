<!-- synchronized report: kem-41/report.md -->
Candidate: ZEN
Family: Lattice (NTRU)
Archive: [ZEN.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/ZEN.zip) (SHA-256: `69eba070320fc6cb365fb6d43d2b74460487732aeb7e607fac2d6c1b3a64a80e`)

## kem-41-1: The numerical DFR model averages over messages while the proof assumes worst-case correctness

Severity: Medium
Status: Proof gap
Layer: Design
Affected: All ZEN parameter rows analyzed in Tables 2 and 3
Discovery: Moderate
Exploitation: Model lower bounds on the per-key worst-case failure probability exceed the averaged estimates, but no attack within 2^80 decapsulations is demonstrated
Credit: Leo Luo (archive sender `leoluo`)
Date: 2026-10-03
Original source: [Leo Luo's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LHS3HBDIJHUIDAKS5Q7H3FXGDY7CLNHZ/)

Theorem 2 in §5.2 writes the PKE correctness error as
`delta_ZEN = max_m Pr[Decrypt(sk, Encrypt(pk,m,rho)) != m]`, with the
probability over key generation and encryption coins. The HHK17 and QROM
Fujisaki--Okamoto theorems cited there require the stronger per-key quantity
`E_sk[max_m Pr_rho[failure]]`, with the maximum inside the expectation over
keys. Thus the specification's displayed definition does not match the cited
theorems. The numerical model in §5.3 is weaker still: it assigns the message
coefficients an independent uniform binary distribution and therefore
averages over messages. Tables 2 and 3 use that model for the stated DFRs and
failure-attack margins.

The original post chooses each message bit as a function of three secret-key
coefficients. Such a per-key choice is admissible under the inner maximum
required by the cited theorems. Its script reproduces the specification's
averaged values and obtains much larger failure-model values, with gaps from
16.88 to 124.42 bits across the six rows. Those values are therefore model
lower bounds on the per-key worst-case quantity the reduction needs, rather
than merely diagnostics. They range from about `2^-104.69` to `2^-214.41`, so
even the largest still requires more than `2^80` decapsulations for an
expected failure. The result establishes a Medium proof gap, not a demonstrated
decryption-failure attack within the evaluation budget or a revised security
level.

### Reproducing

```sh
python3 kem-41/reproduce_dfr_model.py
```

The script is the model published with the forum post, parallelized and given
assertions for all six reported pairs. It labels the second result as a model
lower bound on the per-key worst-case DFR required by the cited reduction.
NumPy is required; the calculation is CPU intensive.
