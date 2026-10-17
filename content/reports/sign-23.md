<!-- synchronized report: sign-23/report.md -->
Candidate: Shuttle
Family: Lattice (Module-LWE/Module-SIS)
Archive: [shuttle.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/shuttle.zip) (SHA-256: `09253fd33c2215098177991db3375cb94e4e4a73a65b019783edabefa5bd8a62`)

## sign-23-1: Reversed transition leaks Shuttle's signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Shuttle-128, -256, and -512 NGCC specification and reference implementations
Discovery: Non-trivial
Exploitation: Equivalent-key recovery and accepted fresh-message forgeries from 175,000/275,000/300,000 valid signatures in independent 128/256/512 tests
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/5ao-Ebsa_Ow/m/zwYJk_Q-BAAJ)
Follow-up source: [Shuttle team's 2026-10-12 PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6QGKAFIAP7LBTXJKXAQA4S6DTJPXJPUG/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §7](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

Figure 1, Eq. (8), and §4.1.1 define `p_v(y)` as the probability of returning `y−v`, but Algorithm 22 sets its flag on the corresponding interval event and returns `y+flag·v`. All three reference `irs.c` files implement that same sign (`irs.c:382–399`). Reversing the intended transition leaves a secret-dependent covariance in valid responses. The constant first component of Shuttle's signing secret supplies a public anchor for estimating the other secret components. An independent driver recovered an equivalent key using only ordinary signatures and the public key, then produced an accepted fresh-message forgery at every level. The original analysis also reports a corrected-sign control; that control has not been independently rerun. The authors' separate [ePrint 2026/1991](https://eprint.iacr.org/2026/1991) uses the matching `y−v` branch, so this finding concerns the NGCC submission.

### Proposed fixes

The team confirms that the submitted Algorithm 22 and reference code reversed the intended transition. It reports changing the final update to `y−flag·v` in revised materials. This change is recorded without evaluating the revised candidate.

### Reproducing

```sh
make -C sign-23 exploit
tools/reproduce.sh sign-23
```

The [independent driver](https://github.com/ngcc-dev/ngcc-harness/blob/dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/security/shuttle_covariance_recovery.c) parses verified signatures, accumulates challenge-conditioned covariance, checks recovered secret coefficients through the public-key relation and key-generation bounds, and signs a fresh message with the resulting equivalent key. It splits ordinary signing queries over eight independent processes by default; no original secret data enters the estimator or public completion. The [original post](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/5ao-Ebsa_Ow/m/zwYJk_Q-BAAJ) describes the same mechanism.

## sign-23-2: Shuttle's ICCS build uses the external DRBG as an XOF

Severity: Low
Status: Confirmed
Layer: Design
Affected: SHUTTLE-128, -256 and -512 ICCS reference builds; the SHAKE build is not affected
Discovery: Trivial
Exploitation: Signer and verifier depend on the particular external RBG stream; the frozen ICCS build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

In the ICCS path, `xof256_init` resets an external `DRNG_ctx` from protocol input and `xof256_squeeze` reads its output (`symmetric.c:73–86`). Shuttle uses this wrapper for public expansion, commitments, challenges and signing/verification transcripts (`sign.c:319,423,702,714`; `polyvec.c:109–135`). The exact ICCS DRBG stream is consequently part of signature interoperability.

The specification makes this choice itself: under the default NGCC mode its unified XOF "collapses onto a single SM3 Hash-DRBG" supplied by the API, and the squeeze schedule is pinned to that DRBG's generate calls (physical p. 109). The reliance on the external RBG's determinism is therefore in the design, not only in the code. The alternate SHAKE path supplies a defined XOF and is outside this finding. The ICCS mode should likewise use a scheme-defined XOF rather than reset an external RBG.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id sign-23-2
```

## sign-23-3: A 128-bit masking seed exposes the Shuttle-128 signing key within the query budget

Severity: Critical
Status: Probable
Layer: Design
Affected: SHUTTLE-128 specification and the Reference, Optimized and Additional implementations; SHUTTLE-256 and SHUTTLE-512 use 256- and 512-bit masking seeds and are not affected within the query budget
Discovery: Moderate
Exploitation: Exact `s1` recovery, public key completion and an accepted fresh-message forgery from publicly detected seed collisions and from a multi-target seed enumeration, both in a reduced-width (20- and 24-bit) seed build of the submitted code; the full 128-bit searches were not run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Algorithm 2 line 10 (physical p. 17) derives the masking seed as `seed_y ← ExpandSigningSeeds(K || rnd || µ || IntegerToBytes(κ, 4), λ/8)`, which is 128 bits for SHUTTLE-128. All three SHUTTLE-128 trees squeeze `SEEDBYTES = LAMBDA/8 = 16` bytes (`params.h:125`, `polyvec.c:116–137`). `seed_y` alone determines the mask `y = SampleY(seed_y)` (`sign.c:461–468`) and the whole rejection-sampling coin stream `0x09 || seed_y` (`sign.c:516–526`). The rejection sampler adds `±s̃ · X^j` for each `j` in the challenge support (`irs.c:301–399`), so every transmitted response component is exactly `z_i = y′_i + s_i · e`, where `y′ = CompressY(y)`, `e` is a ±1 polynomial on the challenge support and `s_0 = 1`. The specification sizes the transcript hashes at 2λ bits for up to `2^{λ/2}` signing queries (p. 13) and allows `q_s < 2^80` signing queries (p. 70), but leaves the masking seed at λ bits.

Two public routes recover the key. In the first, two accepted signatures on different messages share `seed_y`. Then `d_0 = z_0 − z′_0 = e − e′` and `d_i = z_i − z′_i = s_i · d_0` hold exactly in `Z[X]/(X^n+1)`, so `s_1 = d_i · d_0^{-1} mod q` from a single pair. The error term `e′ = b − a_gen − A_gen · s_1` then follows from the public key, which gives an equivalent signing key. Such pairs are found by sorting the verifier's recomputed commitment `EncodeCom(w_h, w_0′)` (`sign.c:764`), because equal `y` gives equal `w`. In the second route, the function `T(pk, seed) = EncodeCom(w_h, w_0)` is computed from the public key and a candidate seed alone. It equals the verifier's commitment for the signature made with that seed, so each guess is tested against all Q signatures with one table lookup. After about `2^128/Q` guesses one seed is found, and `z_1 − y′_1 = (c′, s_1 · c′)` gives `s_1` exactly from that one signature.

Among Q signatures there are about `Q²/2^129` seed collisions, and a conservative 0.91 of them are usable, because `d_0` must be invertible mod q. This gives about 0.37 attack success at the mandatory `2^64` signatures per key, 50% success at about `2^64.30` signatures and about `2^30.9` usable pairs at the `2^80` signing-query budget. The commitment sort costs about `2^64` time and memory. The multi-target route has the same scale: with `2^64` signatures it needs about `2^64` seed guesses. The result is equivalent-key recovery and universal forgery against SHUTTLE-128 below its 128-bit EUF-CMA target. Deterministic signing (`rnd = 0`) is affected in the same way, because both routes act on the seed output.

The experiments change only the width of `seed_y`. With 20 bits kept, 4,096 ordinary signatures gave 9 public commitment matches, and all 9 completed keys whose `s1` equalled the oracle key. A fresh-message signature made with the equivalent key was accepted by the unmodified verifier. Enumerating the 20-bit seed space against 256 signatures hit a signature after 2,623 guesses (about 4,096 expected) and recovered the exact `s1`, which also completed and forged. At the shipped 128-bit width, the true seed of each signature, regenerated with `K`, hits its own table entry, a seed with one bit changed misses every entry, and `s1` is recovered exactly. The shipped-width build gives no commitment match on the same key and DRBG stream, a non-matching pair fails completion, and the changed-message controls reject. The `2^64`-scale searches were not run, so the status is Probable.

### Reproducing

```sh
sh sign-23/reproduce_seed_collision.sh
NGCC_LONG=1 sh sign-23/reproduce_seed_collision.sh
```

The script copies the SHUTTLE-128 reference tree to a temporary directory, inserts the seed truncation directly after `seed_y` is squeezed, and builds a 20-bit and an unmodified variant. It runs the collision route on 4,096 signatures, the multi-target enumeration on 256 signatures and the full-width table identity, with the full-width, non-matching-pair, flipped-seed and changed-message controls (about 30 seconds). `NGCC_LONG=1` uses 24 bits and 16,384 signatures.
