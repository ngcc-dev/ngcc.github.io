<!-- synchronized report: sign-02/report.md -->
Candidate: BiT
Family: Lattice-based
Archive: [BiT.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip) (SHA-256: `698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d`)

## sign-02-1: A 512-bit unsalted message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-512 specification and reference implementation
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

BiT-512 claims 512-bit classical security and normatively computes the message representative `mu = H(tr || M)` as a 512-bit value. This fixed unsalted representative has only 256 bits of generic collision resistance.

After finding distinct messages with the same `mu`, an attacker requests a signature on one and transfers it unchanged to the other. Later signing randomness cannot distinguish the already-colliding messages. The reference implementation uses the same 64-byte representative.

This is a specification-level design break of the advertised 512-bit classical EUF-CMA level. It is a generic `2^256` security ceiling, not a computation performed by the harness.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The check verifies the normative BiT-512 construction on physical PDF pages 18 and 33–34 and the 64-byte source constant.
