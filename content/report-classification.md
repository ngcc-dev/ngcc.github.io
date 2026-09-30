<!-- synchronized report: security/REPORT_CLASSIFICATION.md -->
# Vulnerability report classification

This document defines how NGCC findings receive `Severity`, `Status`, and
`Layer` labels. These labels answer different questions and must be assigned
independently:

- **Severity** describes the demonstrated or bounded security impact.
- **Status** describes the strength of the evidence for the stated finding.
- **Layer** identifies where the vulnerable behavior enters.
- **Remediation burden** describes the cost of removing the behavior. It is
  normally separate context. For side-channel findings, however, the absence
  of a portable and reasonably efficient constant-time realization can be
  evidence that the problem belongs to the design and performance profile.

A finding can therefore be Critical but easy to fix, or Low but expensive to
fix. An expensive constant-time implementation is not automatically a design
flaw, but it becomes design evidence when the construction's claimed software
performance relies on the leaky operation and no portable competitive
constant-time path is supplied or known.

Here *supplied* means the submitters provide the constant-time code, and
*known* means a well-known security-engineering technique exists that the
report itself can describe (for example masked arithmetic, bitslicing,
in-register shuffles, AES instructions, Beneš networks, or a published
constant-time decoder or solver). The same meaning applies to hash functions.

### Proposed fixes

When a report records a publicly proposed change, it places that material in a
`Proposed fixes` subsection and attributes the source. The subsection records
the proposal only: it does not assert that the change is correct, sufficient,
complete, compatible, or secure, and it does not alter the report's evaluation
of the archived submission. A revised candidate requires separate evaluation.

## Security targets

A finding is judged against the NGCC call as well as the specification's own
claims. The canonical documents are published by ICCS.

Public-key algorithms ([call](https://www.niccs.org.cn/niccs/Notice/pc/content/content_1975896137741635584.html)):

- Classical security of 128, 256 and 512 bits, with quantum security of at least
  80, 128 and 256 bits, respectively; an optional 384-bit classical level has a
  192-bit quantum target
  ([Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf)
  §2(1)). "Complexity" covers both time and memory
  ([ICCS feedback](https://www.niccs.org.cn/niccs/Notice/Xi2xTprH.pdf) §5).
- Each signature key pair must support at least 2^64 different messages of up
  to 2^63 bits (§2(2)).
- A KEM's encapsulated key and a key exchange protocol's shared secret key must
  be at least as long as the corresponding classical security level
  ([Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf)
  §2(2)). An output shorter than its level is a direct NGCC-target shortfall,
  even when no separate IND-CCA or key-recovery attack is demonstrated.
- Security is evaluated against an attacker with signatures on up to 2^80
  chosen messages or decapsulations of up to 2^80 chosen ciphertexts
  ([Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/tT7TSQiz.pdf) §1(2)). This is an evaluation ceiling
  for the attacker. For signatures, the operational per-key requirement remains
  2^64 messages; the call gives no analogous per-key session cap for KEMs.
  Classify query-budget findings as follows:
  - **Critical:** a concrete attack costs less than the required level for an
    attacker using at most 2^80 queries and within the per-key usage model that
    the candidate claims or supports. A collision probability or loose proof
    term alone is insufficient: the report must connect it to a primary break,
    such as forgery, key recovery, or distinguishing.
  - **High:** despite a broader security claim, the specification's argument or
    proof bound covers fewer queries (typically 2^64), or becomes too loose at
    2^80, but no concrete attack below the required level within 2^80 queries
    has been shown. Use `Status: Proof gap` unless a specific attack path is
    identified. Missing or insufficient analysis alone is never Critical.
  - No finding solely from the query limit: the argument covers 2^80 queries;
    the query-dependent terms remain negligible at 2^80; or the candidate
    explicitly limits each key to at least the required 2^64 uses, makes no
    broader per-key claim, and no attack is shown within that limit. Record the
    operational limitation where it matters to interpreting the results.
- Signatures must be EUF-CMA or SUF-CMA; KEMs must be IND-CCA2 (§1(1)).

Hash algorithms ([call](https://www.niccs.org.cn/niccs/Notice/pc/content/content_1975892908773478400.html)):

- Collision security of at least h/2 bits and preimage and second-preimage
  security of at least h bits for an h-bit digest, with quantum attacks no
  cheaper than generic ones ([Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/crlRB1ZY.pdf) §1(2)).
- Digest lengths of 512 and 1024 bits (768 optional) and message lengths of at
  least 2^64 − 1 bits ([Submission Requirements](https://www.niccs.org.cn/niccs/Notice/52tbw9IQ.pdf) §2(1)). The targets
  apply to all supported lengths, whatever the specification claims.

## Severity

Rate the strongest consequence supported by the report, including its stated
preconditions and controls. Do not rate the feared consequence of an
uncompleted attack.

### Critical

The report demonstrates a violation of a primary cryptographic security claim
or applicable NGCC target, or gives a concrete attack bound below that target.
Examples include:

- fresh-message forgery, full signing-key recovery, or universal verification;
- challenge-key recovery or a successful IND-CCA, IND-CPA, or key-exchange
  real-or-random distinguishing attack;
- collisions, preimages, or second preimages below the applicable bound;
- an enumerated key, randomness, or transcript space below the applicable
  level;
- a KEM or key-exchange output shorter than the classical level required by
  the call;
- a complete mathematical reduction of the claimed problem to work below the
  claim, even if that work is not currently practical.

NGCC requires a 512-bit classical level and permits an optional 384-bit level.
A demonstrated `2^256` attack against a 512-bit claim is therefore Critical:
practical feasibility is not required when the advertised security bound is
violated.

For quantum attacks, a Grover-iteration count alone is not an end-to-end work
estimate when the oracle is nontrivial. Count the oracle circuit, reversible
arithmetic, memory and parallelization costs under the metric used by the
claim. If those costs could close the reported margin and have not been
bounded, classify the result as an analysis or proof gap rather than a
confirmed below-target attack.

### High

The report establishes a serious security failure but stops short of a complete
primary-claim break. Typical cases are:

- a candidate-specific recovery/forgery method with one clearly identified
  engineering or scale step still unvalidated;
- a strong proof or parameter failure with a well-supported path to violating
  the claim, but without a complete end-to-end witness;
- attacker-controlled memory corruption with credible impact beyond process
  termination;
- a security argument that covers fewer signing or decapsulation queries than
  the call's 2^80 evaluation budget, without a concrete shortfall (see
  Security targets);
- a measured, repeatable secret-dependent oracle together with a
  candidate-specific recovery method, where only the observation channel or
  full-scale run remains open.

A demonstrated violation of a claimed property that the NGCC call does not
require is High rather than Critical. For example, signature malleability that
violates a claimed SUF-CMA property while leaving EUF-CMA intact is High,
because the call accepts either EUF-CMA or SUF-CMA. Failing the designed
security level of a required property is Critical.

Do not use High merely because a defect is expensive to repair. A side-channel
finding can nevertheless be High when it exposes secrets directly and the
construction lacks a portable constant-time realization without a substantial
and justified loss of its advertised performance.

### Medium

The report confirms a security-relevant defect or secret-dependent leakage, but
does not demonstrate recovery, forgery, or a primary indistinguishability
break. Examples include:

- a stable decryption-failure or reaction oracle without a completed recovery;
- repeated secret-dependent control flow or memory access for which a plausible
  local observation model exists;
- a substantive proof, binding, or conformance gap whose concrete attack
  consequence is unresolved;
- an attacker-supplied public key that forces or repeats an honest party's
  derived key, without breaking the scheme's honest-key security game;
- a side-channel repair that requires a material algorithmic rewrite or
  moderate performance/storage cost.

### Low

The demonstrated impact is narrow and presently separated from a cryptographic
claim violation. Examples include:

- denial of service, resource exhaustion, or an API contract error without
  memory disclosure or control-flow impact;
- source-level secret dependence with no measured channel or extraction, when
  a local mask, fixed-bound loop, small-table replacement, or existing
  constant-time path removes it;
- a limited robustness or interoperability defect;
- a disclosed internal status whose existence alone does not defeat the
  claimed transform.

An easy fix may support Low when the demonstrated consequence is already
narrow. It must not downgrade a demonstrated key recovery, forgery, or claim
violation.

### Info

Use Info for withdrawn records or non-security tracking entries. A live
security finding should normally be Low or above.

## Side-channel severity

For timing, cache, branch, division, power, or address-trace findings, answer
these questions in order:

1. Is the varying operand secret or derived from secret data at that point?
2. What can observe it: source inspection only, co-resident cache/process,
   local timing/power, or remote timing/API status?
3. Is the channel measured and repeatable, or only visible in source or
   machine code?
4. Is there a candidate-specific map from observations to a key, shared secret,
   plaintext, or forgery?
5. Has that map been executed end to end with the submitted implementation?

Use the resulting consequence, not the mere presence of a branch or table, as
the primary severity determinant:

| Evidence and consequence | Usual severity |
|---|---|
| Source-level secret branch/address, no measured channel, local repair | Low |
| Repeated secret leakage, measured channel, or material constant-time rewrite; no recovery | Medium |
| Direct fine-grained leakage intrinsic to the advertised fast path, with no competitive constant-time realization supplied or known | High may be justified |
| Stable oracle plus candidate-specific recovery path, one channel/scale gap remains | High |
| End-to-end key/secret recovery or forgery | Critical |

The table is a default, not a substitute for candidate-specific cryptanalysis.
Public-value branches and lookups are not vulnerabilities.

### Hash-function portability rule

For this audit, hash inputs and internal states are treated as potentially
secret. Hash functions are routinely used on passwords, key material,
transcripts containing secret contributions, and other confidential data.

A hash side channel is `Layer: Design` when all of the following hold:

1. the fast construction or the submission's advertised performance relies on
   secret-indexed tables, secret-dependent control flow, or another operation
   that is not portable constant-time;
2. removing that operation requires a different evaluation strategy rather
   than a local mask or canonical lookup replacement;
3. the portable constant-time strategy has a significant demonstrated or
   technically justified performance cost; and
4. no competitive portable constant-time path is supplied by the submitters
   or known as a well-known technique.

Hardware instructions may provide a safe fast path on some targets without
curing the design-portability problem. A primitive that is constant-time only
where a particular instruction-set extension is available is materially
different from an ARX-style construction whose ordinary scalar operations are
naturally constant-time across common processors.

Under this rule, a large byte-indexed table that is central to a hash's speed
can support `High / Design`, even before a complete message-recovery
experiment, when the address trace directly reveals message or state bytes and
the only portable repairs impose a substantial performance loss. The report
must identify the portable repair and measure its cost where feasible; an
unmeasured slowdown must be labelled as an estimate.

## Status

Status records confidence in exactly the claim made by the report:

- **Confirmed:** directly established by source/specification reasoning, a
  mathematical certificate, or a reproducible experiment with appropriate
  controls. `Confirmed` does not imply end-to-end exploitation; the
  `Exploitation` line must state the demonstrated boundary.
- **Probable:** the vulnerable path and consequence are strongly supported,
  but an important source, platform, or experimental step remains unchecked.
- **Lead:** a plausible candidate-specific attack or cost reduction still
  depends on a material unvalidated assumption or experiment.
- **Proof gap:** a stated theorem or reduction is invalid, incomplete, or
  covers an insufficient query range, but no attack of the claimed strength
  follows yet.
- **Withdrawn:** the original finding is false, duplicate, out of scope, or
  superseded. Keep its stable ID and use `Severity: Info`.

`Confirmed` may describe a confirmed source-level leak rated Low, while a High
or Critical attack can remain a Lead. Severity and status must not be collapsed
into one axis.

## Layer

Assign the layer from the root cause, not from repair difficulty:

- **Design:** the normative construction, parameters, proof, or advertised
  portable performance profile contains the weakness. The finding applies to
  conforming implementations, or the submission's fast implementation relies
  on a construction choice whose portable constant-time replacement has a
  substantial justified cost. For hashes, apply the portability rule above.
- **Implementation:** the submitted source deviates from a sounder
  specification or introduces an ordinary API, parser, memory-safety,
  arithmetic, or randomness defect.
- **Side-channel:** the finding depends on observing timing, branches, cache
  addresses, division latency, power, faults, or another non-functional
  execution trace and does not meet the Design criteria above. Use this even
  when the specification claims the supplied code is constant-time; state that
  contradiction in the report.
- **Evaluation:** the issue concerns KATs, archive provenance, build metadata,
  reproducibility, or another evaluation artifact rather than the algorithmic
  security boundary.

The absence of a constant-time implementation ordinarily proves only that the
submitted code is not hardened. To label the root cause `Design`, show that the
specification mandates the observable behavior, that the advertised fast path
structurally relies on it under the hash portability rule, or that the claimed
performance/security profile cannot be retained by a portable constant-time
implementation.

## Remediation burden

Record remediation in the finding body when it helps evaluation:

- **Local:** a mask, fixed bound, canonicality check, small constant-time
  lookup, or already-supplied build path; limited expected cost.
- **Moderate:** a published constant-time decoder/solver, an expanded-key or
  caching change, or another substantial rewrite with credible moderate cost.
- **Architectural:** a change to the key/ciphertext format, core algorithm, or
  performance profile, or a repair with a measured prohibitive cost.

Use measurements where possible. Qualify an unmeasured cost as an estimate.
State tradeoffs: storing an expanded secret changes memory and key handling;
masked scans, sorting/permutation networks, dense multiplication, and
constant-time elimination may change asymptotic or concrete cost. Do not call
such changes local without bounding those costs.

For hash functions, remediation burden also informs the Design classification:
a local masked operation or small in-register substitution remains a
side-channel implementation defect, while replacing a performance-defining
large table or data-dependent evaluation strategy can be a design-level
portability defect.

## Decision procedure

For each finding:

1. Trace public and secret inputs through the vulnerable operation.
2. State the exact observed behavior and attacker model.
3. Identify the strongest demonstrated consequence and its controls.
4. Compare that consequence with the applicable NGCC target and any explicit
   specification claim.
5. Assign `Status` from evidence, `Severity` from consequence, and `Layer` from
   root cause independently.
6. Describe remediation and its expected cost separately.
7. Keep limitations in the report: what was not measured, recovered, forged,
   or proved.

For contest `pseudohash` and `pseudoXOF`, assume ideal replacement primitives
with the same external dimensions and parameters. A finding that disappears
solely on that replacement is not publishable.
