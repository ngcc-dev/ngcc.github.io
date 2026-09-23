<!-- synchronized report: sign-31/report.md -->
Candidate: TSUOV
Family: Multivariate
Archive: [TSUOV.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/TSUOV.zip) (SHA-256: `7ab1effc5fe911c6ab9483ca44a9d9f6d6d911b03eee9f2873b384d97f9aee1d`)

## sign-31-1: A 512-bit prehash caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: TSUOV-512 specification and reference implementation
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

TSUOV-512 claims 512-bit classical security and specifies `mu = Expand_mu(seed_pk || M)` as a 512-bit pseudohash. Only afterward does it hash `mu || salt` to the MQ target.

A generic collision in `Expand_mu` costs about `2^256` evaluations. The two colliding messages have the same `mu`, so the later salt produces the same target for both and a requested signature transfers unchanged. The PDF's own EUF-CMA bound includes a digest-collision term but does not reconcile this birthday ceiling with its claimed 512-bit classical security.

This is a specification-level design break, not an implementation-only truncation.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The check verifies the TSUOV-512 construction on physical PDF pages 18–21 and 27–29 and the submitted 64-byte `mu` constant.

## sign-31-2: Secret-dependent echelon pivots during signing

Severity: Medium
Status: Probable
Layer: Side-channel
Affected: TSUOV reference signer, all three parameter sets
Discovery: Trivial
Exploitation: Local timing side channel; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The signing trapdoor builds a linear system from the private central map and fresh vinegar state. In `tsuov_core.c`, echelon reduction advances `j` until `EQN(j,c)` is nonzero (line 695), branches on rank (753, 785), and retries until consistency (984). These predicates contain secret intermediate values and control the signing execution trace. No full-key extraction or forgery from that trace is claimed; see `constant_time.md`.

### Reproducing

Inspect the included reference source at
`sign-31/Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/tsuov_core.c`,
lines 680–790 and 960–985, and trace the matrix construction from
`TSUOV_Sign`. The corresponding `tsuov_core.c` files for TSUOV_256 and
TSUOV_512 are also included for comparison. This confirms secret-dependent
control flow, not a measured remote timing exploit.
