<!-- synchronized report: sign-25/report.md -->
Candidate: SQIsign2D2
Family: Isogeny
Archive: [SQIsign2D2.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/SQIsign2D2.zip) (SHA-256: `cf635de5eebbdeb7b2212e84f349da4ca878889e0a4a59b463d0c8cdfdb8eeab`)

## sign-25-1: Verifier verdict is decided by stale stack contents

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Level2-eff uncompressed reference implementation
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The Level2-eff uncompressed verifier accepts a full-length all-zero signature, and
accepts a valid signature after the message is changed, when either is verified after
another verification in the same process. The same all-zero signature is rejected when
the stack below the verifier is overwritten first. The verdict is therefore not a
function of the signature.

`protocols_verif_internal` is compiled with `-DNDEBUG`, which removes the point-order
and codomain `assert`s that the verification path relies on, and several further checks
are commented out in the shipped source. For a malformed signature the dim-2 isogeny
chain leaves its codomain partly unwritten, and the final j-invariant comparison then
reads whatever the previous call left on the stack. Two independent tests confirm the
mechanism: overwriting the stack between calls, and rebuilding the instance with
`-ftrivial-auto-var-init=zero`, each make both forgeries reject.

`-DNDEBUG` is the candidate's own default release configuration: the shipped sqisign
Makefiles set `BUILD ?= release` and `RELEASE_CFLAGS := -O2 -DNDEBUG`. The harness mirrors
that default; it did not introduce the assert removal.

A verifier normally processes signatures one after another, so the accepting state is
the ordinary one: an attacker can submit an all-zero signature for a message of their
choice without making any signing query. Acceptance depends on process state rather
than on the attacker's input, which makes the behaviour unpredictable rather than safe.
The compressed instance built from the same tree is unaffected.

All eight uncompressed submitted instances were tested with the same primed-versus-
scrubbed witness. Only Level2-eff uncompressed accepted the forged input; the other
seven rejected it in both states, as did the compressed Level2-eff control. The unsafe
assert-as-validation pattern is shared source, but demonstrated acceptance is therefore
scoped to Level2-eff uncompressed.

The verifier must initialise every value its decision reads, enforce the specified point,
order and codomain conditions unconditionally rather than through `assert`, and reject
zero or malformed decoded responses before protocol verification.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-25
tools/ngcc_attack sig-uninit-verdict sign-25/lib/libSQISign2Dsquare-Level2-eff_uncompressed.so
```

The check verifies one all-zero signature twice, once after a genuine verification and
once after overwriting the stack, and reports the two verdicts. The compressed instance
is run as a control and rejects both. `tools/reproduce.sh` runs this together with the
other supported runtime witnesses and their controls. See `tools/README.md`.

## sign-25-2: Isogeny prime sizing relies on the former square-root attack cost

Severity: Medium
Status: Lead
Layer: Design
Affected: All eight SQIsign2D2 parameter sets' prime-sizing rationale
Discovery: Moderate
Exploitation: Asymptotic result; concrete key-recovery cost unresolved
Credit: Further extension to Yintong Luo's analysis (GitHub @yintong16); underlying algorithm by Benjamin Wesolowski
Date: 2026-09-23
Original source: [Related SQIsign parameter issue #10](https://github.com/ngcc-dev/ngcc-harness/issues/10)

Further extension to Yintong Luo's analysis: SQIsign2D2 §4.1 also chooses `log2 p ≈ 2λ` because it prices generic classical attacks at `p^1/2`. [Wesolowski, ePrint 2026/1486](https://eprint.iacr.org/2026/1486) improves the underlying supersingular-isogeny problem to heuristic `p^(1/3+o(1))` time and memory. The archived Level3-eff prime is even identical to SQIsign2D-push1/2's Level-3 prime. This supersedes the square-root sizing premise for **all** submitted levels, including Level1 and Level2; the bare `p^1/3` exponent for Level1-eff is about 84.9 against a 128-bit claim. The paper cautions that superpolynomial overhead and memory may dominate at concrete sizes, particularly for the smaller levels. No particular set is asserted to have a concrete below-claim attack, and no full-size key recovery or forgery is claimed here.

[Mamah's later concrete time–space analysis](https://eprint.iacr.org/2026/1821), updated 2026-09-23, finds that the optimistic improvement can require prohibitive memory even for generic 256- and 512-bit SQIsign primes. It does not cost these archived NGCC instances, so this remains a lead rather than a concrete break.

### Reproducing

Compare §4.1 and §4.2 of `sign-25-spec.pdf` with the cited attack paper, including the Level1, Level2, Level3, and Level5 primes.
