<!-- synchronized report: sign-08/report.md -->
Candidate: DARTS
Family: Lattice-based
Archive: [DARTS.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DARTS.zip) (SHA-256: `1846cfe63f0cef83e2e0ca21f5dcadce3c4b16da33713957be6d156e2a9e6e95`)

## sign-08-1: The implemented message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: DARTS-512 reference implementation and specification
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

DARTS-512 claims 512-bit classical security and binds messages through the unsalted representative `mu = H1(pk, M)`. The submitted implementation emits only 64 bytes. A generic collision therefore costs about `2^256` evaluations and transfers a requested signature from one colliding message to the other.

The PDF names `H1` but does not define its output length. The concrete implementation ceiling is confirmed, while the missing length prevents classifying 64 bytes as a clean normative design parameter. This is an implementation security ceiling and a specification omission.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The check verifies the DARTS-512 algorithm on physical PDF pages 4, 8, and 12–13 and traces its 64-byte `mu`.
