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

Severity: High
Status: Lead
Layer: Design
Affected: Level1-eff has a well-supported path to a below-target attack; all eight parameter sets use the superseded prime-sizing rationale
Discovery: Moderate
Exploitation: Published analysis of a nearby prime and current parameter-selection work indicate a serious Level1-eff shortfall, but no candidate-specific below-target cost or full-size key recovery has been established
Credit: Yintong Luo (GitHub @yintong16); concrete reassessment by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; underlying algorithm by Benjamin Wesolowski
Date: 2026-09-23
Original source: [Related SQIsign parameter issue #10](https://github.com/ngcc-dev/ngcc-harness/issues/10)

SQIsign2D2 §4.1 chooses `log2 p ≈ 2λ` because it prices generic classical attacks at `p^1/2`. [Wesolowski, ePrint 2026/1486](https://eprint.iacr.org/2026/1486) improves the underlying supersingular-isogeny problem to `p^(1/3+o(1))` time and memory. [Ouyang, Wei and Xu](https://arxiv.org/abs/2610.21488) subsequently proved the smoothness property used by the algorithm, making that asymptotic result unconditional.

[Mamah's concrete analysis](https://eprint.iacr.org/2026/1821) estimates `2^[138.78,143.51]` gates for the old 250.3-bit SQIsign Level-I prime with at most `2^80` stored entries. Level1-eff uses a nearby 254.6-bit prime. Scaling only the attack's dominant fixed-memory square-root term would add about `(254.6-250.3)/2 = 2.2` bits, suggesting `2^[140.9,145.7]` gates. This is context rather than a candidate-specific attack estimate: it does not recompute the smoothness or root-finding factors, its midpoint is above the roughly `2^143`-gate AES-128 reference, and its interval crosses that reference.

[SQIsign v3](https://sqisign.org/spec/sqisign-20260901.pdf) now uses approximately 326-, 505- and 669-bit primes for 128-, 192- and 256-bit targets. Its deliberately attacker-favourable model supports the seriousness of the parameter concern, but gives a lower bound used for parameter selection rather than an executable attack cost. For Level1-sec and the higher submitted profiles, the old sizing rationale is superseded but no candidate-specific concrete below-target cost is asserted here. No full-size key recovery or forgery was run.

Reclassified from Medium to High on 2026-10-16. The status remains Lead because a candidate-specific below-target cost has not been established.

### Reproducing

Compare §4.1 and §4.2 of `sign-25-spec.pdf` with the cited attack papers and current parameter analyses. Level1-eff has `log2 p = 254.63`; the published concrete row uses `p = 5·2^248-1`, with `log2 p = 250.32`.

## sign-25-3: Detached compact challenge enables one-query message-retargeting forgeries

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All eight compact SQIsign2D2 parameter sets; uncompressed mode is not affected by this attack
Discovery: Moderate
Exploitation: One signing query, followed by one public commitment reconstruction and hash per fresh-message forgery
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-28
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2M2QPP46J6K3E623EXZXGCU2QFZFDIL6/)

The compact verifier reconstructs the challenge curve from the response and the commitment curve from the encoded dual path before it reads the transmitted challenge. It then checks only that

`chall = H(pk || j(E_com) || message)`.

The challenge is not used to verify that the reconstructed forward challenge isogeny has the recovered challenge curve as its codomain, or that it is compatible with the encoded dual path. Thus the geometric acceptance predicate is independent of both the transmitted challenge and the message.

After obtaining one signature `(response,path,chall_0)` on any message, an attacker publicly reconstructs the same `E_com`, hashes it with an arbitrary fresh target message, and replaces only `chall_0` with that digest. Every geometric check is unchanged and the final hash comparison now holds for the target. This is a direct one-query EUF-CMA forgery, not signature malleability. It violates the submission's claimed EUF-CMA security at every level and is therefore Critical.

The pinned artifact performs three fresh-message forgeries for each of the eight compact reference instances. All 24 forgeries were accepted; controls verify the original signature, reject it on the target before modification, reject each retargeted signature on the source message, and confirm that no byte outside the serialized challenge field changed. The attack uses only the public key, signature, and target message. The original 2025 CompactSQIsign2D2 construction includes an additional forward-to-dual binding equality and is outside this result.

Verification must use the hash-derived challenge to construct the forward challenge kernel and check that its codomain and dual-kernel relation agree with the path reconstructed from the response.

### Reproducing

```sh
sh sign-25/reproduce_compact_retarget.sh
```

The wrapper downloads and checks out the [pinned public artifact](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/a30462dce48bd484d7c8c4d5b1f971e7dfebacfd/SQIsign2D2), builds the unmodified compact implementations from this candidate directory, and requires eight `status=PASS` result lines.
