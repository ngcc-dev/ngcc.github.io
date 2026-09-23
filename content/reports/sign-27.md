<!-- synchronized report: sign-27/report.md -->
Candidate: SQIsignTriangle
Family: Isogeny/quaternion signature
Archive: [SQIsignTriangle.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/SQIsignTriangle.zip)

## sign-27-1: An all-zero signature aborts the verifier process

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: All four submitted reference levels; independently rerun on SQIsignTriangle_lvl1
Discovery: Trivial
Exploitation: Remote denial of service where untrusted signatures reach an unisolated verifier; no forgery or key recovery shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The submitted verifier passes attacker-controlled encoded signature data to `compressed_aux_basis_from_bytes`, which asserts that the decoded exponent `e_rsp` is in range. An all-zero signature fails that assertion and calls `abort()` instead of returning invalid-signature status. The existing bounded security sweep recorded the same assertion in all four levels. Rebuilding level 1 from source reproduced exit code 134; its honest KAT passes. This is a process-availability flaw only, and the result with assertions disabled has not been established.

### Reproducing

```sh
make -C sign-27 lib/libSQIsignTriangle_lvl1.so
make -C security ngcc_security
security/ngcc_security sign-27/lib/libSQIsignTriangle_lvl1.so sig-zero
```

The last command intentionally aborts with `encode_verification.c:216` and exit status 134. `make -C sign-27 test-SQIsignTriangle_lvl1` is the passing honest-signature control.
