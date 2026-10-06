<!-- synchronized report: sign-31/report.md -->
Candidate: TSUOV
Family: Multivariate
Archive: [TSUOV.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/TSUOV.zip) (SHA-256: `7ab1effc5fe911c6ab9483ca44a9d9f6d6d911b03eee9f2873b384d97f9aee1d`)

## sign-31-1: A 512-bit prehash caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: TSUOV-512 specification, reference and optimized implementations
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

TSUOV-512 claims 512-bit classical security and specifies `mu = Expand_mu(seed_pk || M)` as a 512-bit pseudohash. Only afterward does it hash `mu || salt` to the MQ target.

A generic collision in `Expand_mu` costs about `2^256` evaluations. The two colliding messages have the same `mu`, so the later salt produces the same target for both and a requested signature transfers unchanged. The PDF's own EUF-CMA bound includes a digest-collision term but does not reconcile this birthday ceiling with its claimed 512-bit classical security.

This is a specification-level design break, not an implementation-only truncation.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-31-1
```

The check verifies the TSUOV-512 construction on physical PDF pages 18–21 and 27–29 and the submitted 64-byte `mu` constant.

## sign-31-2: Secret-dependent echelon pivots during signing

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: TSUOV reference signer, all three parameter sets
Discovery: Trivial
Exploitation: Local timing side channel; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The signing trapdoor builds a linear system from the private central map and fresh vinegar state. In `tsuov_core.c`, echelon reduction advances `j` until `EQN(j,c)` is nonzero (line 695), branches on rank (753, 785), and retries until consistency (984). These predicates contain secret intermediate values and control the signing execution trace. No full-key extraction or forgery from that trace is claimed; see `constant_time.md`.

Constant-time fix (moderate, hence Medium): use constant-time Gaussian elimination that adds candidate pivot rows under masks, a well-known technique in constant-time UOV and MAYO implementations. It processes every row at every step, a moderate cost; a retry on a singular system is the usual accepted exception.

### Reproducing

Inspect the included reference source at
`sign-31/Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/tsuov_core.c`,
lines 680–790 and 960–985, and trace the matrix construction from
`TSUOV_Sign`. The corresponding `tsuov_core.c` files for TSUOV_256 and
TSUOV_512 are also included for comparison. This confirms secret-dependent
control flow, not a measured remote timing exploit.

## sign-31-3: Allocation failure reuses a stale message representative

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All three reference and optimized TSUOV implementations
Discovery: Moderate
Exploitation: An attacker-supplied oversized message can induce acceptance of a prior signature on a different message under a constrained verifier
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FQMMQX3BFR473NUCIPK5IIFXKO3X6QKO/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/6756633dfa096e729aeeb4dfce281ad5f345091f/tsuov-impl-failopen)

`Expand_mu` returns without changing its output when `malloc(seed_len+message_len)` fails (`tsuov_core.c:415–425`). Signing and verification do not propagate that failure. After one valid verification initializes the reused stack slot, forcing the allocation for a 256 MiB unrelated message to fail leaves the previous `mu` in place, and the prior signature is accepted for the new message in all six trees. Signing has an analogous stale-output path.

An attacker can choose the message length and exhaust a constrained verifier's allocation budget, then reuse a signature already checked in the same process. The accepted signature is on a new message, but the witness requires a memory limit and a primed stack; remote triggering and reliability outside those conditions are untested. The demonstrated forgery path with these preconditions is High.

### Reproducing

```sh
./sign-31/reproduce_implementation_findings.sh
```

## sign-31-4: Declared public-key and signature lengths are ignored

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All three reference and optimized TSUOV implementations
Discovery: Trivial
Exploitation: Out-of-bounds reads from short buffers and acceptance of trailing bytes; no disclosure demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FQMMQX3BFR473NUCIPK5IIFXKO3X6QKO/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/6756633dfa096e729aeeb4dfce281ad5f345091f/tsuov-impl-failopen)

`sig_verify` discards `pk_len_bytes` and `sn_len_bytes` and parses fixed-size fields (`SIG_AlgorithmInstance.c:100–118`). Short buffers therefore cause out-of-bounds reads; longer signatures with trailing bytes are accepted. AddressSanitizer reproduced the reads across all parameter sets and both implementation families. No memory disclosure, write, or control-flow effect follows from this length defect alone, so it is Low.

### Reproducing

```sh
./sign-31/reproduce_implementation_findings.sh
```

## sign-31-5: Impossible-length input wraps the message allocation

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All three reference and optimized TSUOV implementations
Discovery: Trivial
Exploitation: AddressSanitizer detects a heap write only when the caller claims a near-2^64-byte buffer it cannot supply
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FQMMQX3BFR473NUCIPK5IIFXKO3X6QKO/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/6756633dfa096e729aeeb4dfce281ad5f345091f/tsuov-impl-failopen)

The same `Expand_mu` allocates `TSUOV_SEED_LEN + message_length` without checking addition overflow, then copies the public-key seed and the caller's message. A near-`SIZE_MAX` length wraps to a small allocation before the fixed seed copy already writes beyond it. AddressSanitizer confirms this in every parameter set and both implementation families. The trigger requires a caller to claim a message of at least `2^64 - TSUOV_SEED_LEN` bytes without providing such a buffer. That is not a valid message in a 64-bit address space, so no realistic remote write path is demonstrated; the missing length check is Low.

### Reproducing

```sh
./sign-31/reproduce_implementation_findings.sh
```

## sign-31-6: Noncanonical field encodings create signature and public-key aliases

Severity: Medium
Status: Confirmed
Layer: Design
Affected: TSUOV specification and all reference and optimized implementations
Discovery: Trivial
Exploitation: Distinct encodings of the same signature or public key; no fresh-message forgery
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance; independently confirmed by LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FQMMQX3BFR473NUCIPK5IIFXKO3X6QKO/) and [LK-PQC-Hunter's independent post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/URUZDSBCKZL4XEH7FC7RL6GNW75OG6GI/)

Five-bit field encodings do not reject the unused value 31 for `q=31`. Unpacking reduces it to zero, so changing zero coefficients to 31 in a signature or the `P3` portion of a public key preserves verification. The specification's `Unpack` step likewise has no canonical rejection and claims EUF-CMA only (Algorithm 3, physical p. 21; Theorem 6.12, p. 30). The 128/256 implementations additionally ignore final public-key padding bits.

All coefficient rewrites cross-verified between reference and optimized implementations for all three sets, with honest controls. Signature and public-key aliases undermine canonical identity and strong unforgeability, though the specification claims only EUF-CMA and no fresh-message forgery follows. As with other accepted encoding aliases, this is Medium.

### Reproducing

```sh
./sign-31/reproduce_implementation_findings.sh
```

## sign-31-7: The TSUOV-128 EUF-CMA proof loses its bound at 2^64 salt trials

Severity: High
Status: Proof gap
Layer: Design
Affected: TSUOV-128 specification and its reference and optimized parameter sets
Discovery: Trivial
Exploitation: Proof gap; no concrete forgery follows from the term alone
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

TSUOV-128 uses a 128-bit signature salt (specification §4.4; `tsuov_params.h:19,79`). Lemma 6.10 and Theorem 6.12 of the submitted specification bound the salt-collision game hop by `(Q_h + Q'_s)Q'_s 2^-λ`, where `Q'_s` counts all honest signer salt trials and `λ=128`. At `Q'_s=2^64` this term is already at least one even with `Q_h=0`. The bound becomes vacuous at the candidate's required per-key capacity of `2^64` messages and cannot substantiate security through the NGCC `2^80` chosen-message evaluation budget.

This is a shortfall in the submitted reduction; it does not establish a collision attack or a forgery against TSUOV-128.

### Reproducing

```sh
python3 sign-31/certify_salt_bound.py
```

The certificate checks the source salt width, locates the stated proof terms in the submitted PDF and evaluates the bound at `2^64` trials.
