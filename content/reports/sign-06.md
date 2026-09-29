<!-- synchronized report: sign-06/report.md -->
Candidate: COMPASS-SIG
Family: Lattice-based
Archive: [COMPASS-SIG.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/COMPASS-SIG.zip) (SHA-256: `ce88066506fe9b58c300b3ca51462c7a8350484d88ad5b8a9c9f17b5152ca820`)

## sign-06-1: The implemented message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: COMPASS-SIG-384 and COMPASS-SIG-512 reference implementations; specification leaves the hash length undefined
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

COMPASS-SIG binds the message through the unsalted value `mu = H(pk || m)`, but the PDF does not define `H`'s output length. The COMPASS-SIG-384 and COMPASS-SIG-512 implementations instantiate `mu` as 64 bytes. A generic collision in this fixed 512-bit representative costs about `2^256` evaluations.

An attacker finds two messages that collide under the target public key, obtains a signature on one, and transfers it to the other. The source choice caps both implementations below their respective 384- and 512-bit classical EUF-CMA claims. Because the PDF leaves the hash length unspecified, this is classified as an implementation ceiling and specification omission rather than a clean design parameter.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The `sign-06-1` check verifies the construction on physical PDF pages 5 and
8–10 and the submitted 384- and 512-bit constants.

## sign-06-2: The implementation expands the entire key pair from a 256-bit root

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: COMPASS-SIG-384 and COMPASS-SIG-512 reference implementations and specification
Discovery: Trivial
Exploitation: Approximately 2^256 key-generation trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The COMPASS-SIG specification requires an `n`-bit KeyGen seed. The 384- and 512-bit implementations instead draw one 32-byte root and deterministically expand the complete key pair from it.

The generated public-key support is at most `2^256`; exhaustive root enumeration and public-key matching recovers a target signing key in at most that many trials. This is below both implementations' classical claims and is an implementation/specification conformance break.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The `sign-06-2` check verifies the KeyGen seed on physical PDF pages 7 and 13
and the submitted 384- and 512-bit constants.

## sign-06-3: Rejected signatures leak heap memory without bound

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All four COMPASS-SIG reference and optimized parameter sets
Discovery: Trivial
Exploitation: Repeated verifier calls exhaust process memory; no cryptographic break or memory disclosure shown
Credit: Yamin Liu and Tianyuan Xie, with AI assistance
Date: 2026-09-28
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ZIYQJY4LKZDNLUMVNX4AXP7BEQNRGQDS/)

The blockwise XOF allocates `squeeze_buf` and `stream_extra` in
`symmetric-shake.c:21,259–260,281–282`. Its private `state_cleanup` is used by
the one-shot wrappers, but not by the signing, key-generation, or verification
owners of blockwise states. In particular, a structurally valid signature with
an incorrect challenge reaches `sign.c:374,381,408`, is rejected, and leaves
every allocation behind. The reference and optimized copies of this code are
identical. Because verification consumes untrusted input, repeated requests can
exhaust a long-running verifier's memory; this is an availability defect, not a
forgery or disclosure result.

### Reproducing

```sh
make -C api harness
make -C sign-06
python3 sign-06/reproduce_verify_leak.py sign-06/lib/libCOMPASS-SIG-*.so
```

For each set, the witness creates a valid signature, changes its public
challenge so verification traverses the allocating path and rejects it, and
measures 500 calls in an isolated process. Resident memory grows by tens of
KiB per call. As a control, the same number of all-zero encodings are rejected
before that path without per-call growth.

## sign-06-4: XOF block replay duplicates every high-level secret polynomial

Severity: High
Status: Confirmed
Layer: Implementation
Affected: COMPASS-SIG-384 and COMPASS-SIG-512 reference and optimized implementations
Discovery: Trivial
Exploitation: Confirmed reduction of the secret dimension; public-key-only recovery cost remains unresolved
Credit: Yamin Liu and Tianyuan Xie, with AI assistance
Date: 2026-09-29
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5GFCMSYVGVAEWZQAYUR6QFMGBFDYQ6MT/)

When `fill_squeeze` enlarges its buffered XOF output, it recomputes the longer prefix and resets `state->squeeze_pos` to zero (`symmetric-shake.c:11–30`). Consecutive 136-byte squeezes therefore return the same first block instead of consecutive blocks. This remains a defect when the contest placeholder is replaced by an ideal prefix-consistent XOF with the same interface.

The 384- and 512-bit secret samplers need a second block for their 512-coefficient polynomials. That block replays the first, so every sampled secret polynomial has a suffix equal to its prefix. Fresh deterministic keys reproduced duplicated tails of 84–117 coefficients in all 11 COMPASS-SIG-384 secret polynomials and 80–133 in all 14 COMPASS-SIG-512 polynomials, leaving mean free-coordinate fractions about 0.797 and 0.800. The 128- and 256-bit sets consume only one block and are controls.

The reporters' full-`t` lattice model reduces the estimated 384-bit attack from about `2^442` to `2^257`–`2^274`, and the 512-bit attack from about `2^523` to `2^281`–`2^300`. The public key exposes rounded `t`, however, and two public-key-only analysis routes disagree; no practical key recovery is claimed. The confirmed severe parameter-distribution failure and candidate-specific recovery path warrant High, not Critical. Preserving the old read position when the prefix buffer grows fixes the replay; the high-level KATs must then change.

### Reproducing

```sh
make -C sign-06
python3 sign-06/reproduce_xof_replay.py
```

The witness checks all eight parameter-specific reference and optimized wrapper copies, generates fresh keys through the submitted API, unpacks every `s1` and `s2` polynomial, and requires a long prefix-equal suffix in every high-level polynomial. Fresh 128- and 256-bit keys are negative controls.
