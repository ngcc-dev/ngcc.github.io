<!-- synchronized report: kem-15/report.md -->
Candidate: FLIT
Family: Lattice (NTRU-like KEM)
Archive: [FLIT.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/FLIT.zip) (SHA-256: `6c560f434b347fbac8334f55b9ba2838cb1cf885d5aa25e95acb66ed6c6de0fe`)

## kem-15-1: FLIT512 reference and optimized implementations silently derive different keys

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted FLIT512 reference and AVX2 implementations
Discovery: Trivial
Exploitation: Mixing the two official implementations causes silent session-key mismatch
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-29
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UJMEBKKD3OZ3QHPHEARB2WBINLVX5RR7/)

The FLIT512 AVX2 `poly_compress_and_pack` omits the reference implementation's `& 0x1FF` reduction in its nine-bit compression branch (`poly.c:299–331`). For coefficients 3326–3328 the reciprocal quotient is 512; the reference maps it to zero, while the optimized packer lets bit 9 spill into the next field.

Both implementations self-verify. With the same seed they also generate identical public and secret keys, but their ciphertext and shared secret differ. Each cross-decapsulation returns `0` while deriving a key different from the sender's; the API uses `0` for both its acceptance and implicit-rejection paths, so this value does not show which path ran. Across the ten submitted KAT seeds, ciphertext and shared secret differ in eight records; the local fresh-seed witness below produces a one-byte ciphertext difference and silent mismatch in both directions.

This is a limited interoperability and correctness failure, not a confidentiality break, hence Low.

Follow-up response: the [FLIT team's 2026-09-29 post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VRUXVADZDQ6DMCIH2BPPGKOF54UOFAOI/) confirms the archived package's interoperability behavior and the missing mask as its cause. The team says it had independently identified the defect before the public report.

### Proposed fixes

The [FLIT team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VRUXVADZDQ6DMCIH2BPPGKOF54UOFAOI/) proposes adding `& 0x1FF` in the optimized nine-bit compression branch and points to its [updated implementation](https://github.com/MathEternal/FLIT-NGCC). This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kem-15/reproduce_interop.py
```

The script builds both archived implementations in a temporary directory, exercises their submitted APIs with one common seed, checks self-decapsulation controls, and prints `CONFIRMED kem-15-1` only when both cross-decapsulations silently derive the wrong key.
