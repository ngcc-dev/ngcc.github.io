<!-- synchronized report: sign-24/constant_time.md -->
# Constant-time review — 24 Sigurd

Scope: reference implementation, representative instance only: `Implementations/Reference_Implementation/Sigurd-128/SIG_AlgorithmInstance.c`. Other instances and optimized implementations have not been proven source-equivalent. This is a source-level triage, not a constant-time certification.

Secret: witness/secret key and per-proof random tapes until revealed. Public: verification key, message, Fiat–Shamir challenge and opened transcript.

- Branch/loop trace: `Implementations/Reference_Implementation/Sigurd-128/SIG_AlgorithmInstance.c:158` — `sig_pack_y_bits` branches on a *public syndrome* reconstructed from the key; this is public-value control flow, not a finding.
- Long-term-secret branch: every signing operation rebuilds the public state and conditionally updates `y_bits` on `e_bits[col]` (`Reference_Implementation/Sigurd-128/sig_core.c:567,589–592`). The same construction appears in all three reference and optimized trees. LK-PQC-Hunter reports repeatable callgrind line-count differences under a controlled secret-only key axis. The source-level defect is tracked as `sign-24-3`; no external timing/cache channel or recovery has been demonstrated.
- Table lookups and division/remainder: this source triage does not certify their absence or constant-time compilation. Only the explicitly traced operands above are classified. Public lengths, fixed parameters and verifier checks are not findings.

Assessment: The secret-dependent state-reconstruction branch is tracked as the Low implementation finding `sign-24-3`. A compiler/architecture-specific timing and cache test is still needed before claiming an observable channel or stronger consequence.

Recheck the cited source line and its caller before reusing this result. A timing claim requires controlled same-public-input tests with changed secret state and a public-value control.
