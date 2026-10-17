<!-- synchronized report: sign-02/report.md -->
Candidate: BiT
Family: Lattice-based
Archive: [BiT.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip) (SHA-256: `698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d`)

## sign-02-1: A 512-bit unsalted message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-512 specification, reference and optimized implementations
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [BiT team's 2026-10-12 PKC Forum update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ONSUXJ3MD4PYXHBRPIVGKBXW5CZ7ONIT/)

BiT-512 claims 512-bit classical security and normatively computes the message representative `mu = H(tr || M)` as a 512-bit value. This fixed unsalted representative has only 256 bits of generic collision resistance.

After finding distinct messages with the same `mu`, an attacker requests a signature on one and transfers it unchanged to the other. Later signing randomness cannot distinguish the already-colliding messages. The reference implementation uses the same 64-byte representative.

This is a specification-level design break of the advertised 512-bit classical EUF-CMA level. It is a generic `2^256` security ceiling, not a computation performed by the harness.

### Proposed fixes

The team reports revising BiT-512 to bind the message and its encoded length directly into the Fiat–Shamir challenge, instead of a fixed-length prehash. It points to [revised materials](https://light-lattice.org/bit/). This proposal is recorded without evaluating the revision.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-02-1
```

The check verifies the normative BiT-512 construction on physical PDF pages 18 and 33–34 and the 64-byte source constant.

## sign-02-2: A shared bimodal sign leaks an equivalent BiT-128 signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-128; the same shared-sign construction appears in the other sets, but their recovery costs were not established
Discovery: Non-trivial
Exploitation: Equivalent-key recovery from 200,000 public signatures and a fresh-message forgery accepted by the unmodified verifier; a changed-message control rejects
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/84_EKMOtk_M/m/ZNMqLQ07BAAJ)
Follow-up source: [BiT team's 2026-10-12 PKC Forum update](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ONSUXJ3MD4PYXHBRPIVGKBXW5CZ7ONIT/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §8](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

BiT uses one hidden sign for the entire response, but its rejection rule corrects each coefficient against a *scalar* mixture. The joint response remains a mixture of two product distributions and retains secret-dependent cross-coordinate correlations even when the individual marginals have the intended distribution. The response to the known constant component gives an observation of the common sign, allowing the remaining response components to reveal the signing secret statistically. Figures 2 and 4 specify a single sign bit per signature with coefficientwise rejection; §3.1.3’s assertion that “z is independent of b” fails for the joint response. The reference source has the same pattern (`sign.c:134–153`, `sample.c:124–259`). The mechanism does not depend on a hash weakness.

The released public-transcript attack streams 200,000 signatures from an ordinary signing oracle, statistically recovers a candidate key, repairs low-confidence coefficients by a public search when the candidate fails the compressed public-key relation (in our run, 1,596 candidates over 24 search bits), completes an equivalent key that satisfies the relation, and produces a fresh-message signature accepted by the unmodified BiT-128 verifier. A changed-message control rejects. We reproduced its fixed key-0 experiment in 164 CPU-seconds on a single-threaded `Intel Core Processor (Broadwell, IBRS)` validation VM; the attack never reads or compares the generated secret key. This upgrades the finding from Probable to Confirmed. The authors report three of four fixed keys succeeding at 200,000 signatures and the fourth at 250,000; no success-rate claim beyond those experiments is made.

Follow-up analysis: the [BiT team's 2026-09-29 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/74QWBAYF4KZYN5HDHM2ROENQUDVWAUGT/) confirms this shared-sign issue and says that the distinct compressed-public-key leakage reported for CS also applies to the earlier BiT version. No BiT-specific derivation, transcript, or witness for that second route accompanied the response. Since the confirmed shared-sign route already yields equivalent-key recovery and forgery, the additional statement is retained as follow-up evidence rather than assigned a separate vulnerability ID.

### Proposed fixes

The team reports replacing coefficientwise rejection with a parabolic rejection sampler over the full response vector, and transmitting the complete public key instead of compressing it. It presents these as responses to the shared-sign and compression routes, respectively. The revision is recorded without evaluation.

### Reproducing

```sh
sign-02/reproduce_bimodal_key_recovery.sh
```

The wrapper downloads and hash-checks both Feussner's [attack package at commit `91f2ddf`](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/91f2ddf0590a24ad39afc2ce2ee4f2627ec54726/BiT) and the official BiT submission archive. It runs the fixed 200,000-signature key-0 experiment and requires equivalent-key recovery, fresh-message acceptance and changed-message rejection.

## sign-02-3: Mask-seed collisions recover an equivalent BiT-128 signing key

Severity: Critical
Status: Probable
Layer: Design
Affected: BiT-128 specification, reference and AVX2 implementations; BiT-256 and BiT-512 use 256- and 512-bit mask seeds and are not affected within the query budget
Discovery: Moderate
Exploitation: Equivalent-key recovery and an accepted fresh-message forgery from publicly detected seed collisions in a reduced-width (16- and 24-bit) seed build of the submitted code; the full 128-bit birthday search was not run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Figure 5 (physical p. 19) derives all signing masks from `seed_y ∈ {0,1}^κ := XOF(ρ′ || rnd || µ)`, with κ = 128 for BiT-128. The reference code squeezes `BIT_SEEDBYTES = 16` bytes (`sign.c:99–103`, `params.h:47`), and every mask and rejection coin of a signing call is then expanded from `(seed_y, nonce_y)` (`sample.c:20–25`); the AVX2 tree is the same (`sign.c:101–102`). Two signing calls on different messages that draw the same `seed_y` therefore draw the same sequence of masks `y`, and they return the same `y` whenever their rejection histories coincide. The bimodal sign bit `b` comes separately from the DRBG.

For such a pair, `z_{1,0} = y_0 + (−1)^b c` and `z_{1,1} = y_1 + (−1)^b s_0 c` (`sign.c:148–151`) give `d_0 = z_{1,0} − z′_{1,0} = (−1)^b c − (−1)^{b′} c′` and `z_{1,1} − z′_{1,1} = s_0 · d_0` exactly in `Z_q[X]/(X^n+1)`. A negacyclic linear solve gives `s_0`, and the remaining key material `(e′, b_0′)` follows from the public relation `A_0 s_0 − γ_B b_1 = b_0 − e`. The result is an equivalent signing key. The pairs are found from public data alone: equal `y` gives an equal verifier commitment `w′` (`sign.c:260–262`), so sorting signatures by `w′` finds them.

About 0.22 of seed collisions are usable (112 completed keys from 512 expected collisions, measured in the reduced-width build). Among Q signatures the expected number of usable pairs is therefore about `0.22 · Q²/2^129`. This gives about 10.3% attack success at the mandatory `2^64` signatures per key, 50% success at about `2^65.33` signatures, one expected usable pair at about `2^65.60`, and about `2^28.8` usable pairs at the `2^80` signing-query budget. Sorting the commitments costs about `2^66` time and memory. Theorem 2 (physical p. 24) treats `y` as fresh per signature; its loss term contains no `q_S² · 2^−κ` term for repeated mask seeds. The result is equivalent-key recovery and universal forgery against BiT-128 below its 128-bit EUF-CMA and SUF-CMA target.

The experiment changes only the width of `seed_y`. With 16 bits kept, 8,192 ordinary signatures on distinct messages gave 112 public commitment matches, and all 112 completed equivalent keys. The recovered `s_0` equalled the oracle key, and a fresh-message signature made with the equivalent key was accepted by the unmodified verifier. The shipped 128-bit build produced no match on the same key and DRBG stream, a non-matching pair fails completion, and the changed-message control rejects. The `2^64`-scale collision search itself was not run, so the status is Probable. The equivalent key has a short `e′` consistent with the public key, not the original `e`, but the signatures it produces verify.

### Reproducing

```sh
sh sign-02/reproduce_seed_collision.sh
NGCC_LONG=1 sh sign-02/reproduce_seed_collision.sh
```

The script copies the BiT-128 reference tree to a temporary directory, inserts the seed truncation directly after `seed_y` is squeezed, builds a 16-bit and an unmodified variant, and runs the public collision search, completion and forgery on 8,192 signatures each (about 25 seconds). It requires every match to complete an equivalent key, the forgery to verify, the changed message and a non-matching pair to reject, and the full-width control to find no match. `NGCC_LONG=1` uses 24 bits and 65,536 signatures (about 2.5 minutes).
