<!-- synchronized report: kex-08/report.md -->
Candidate: NIIKE
Family: Isogeny-based non-interactive key exchange
Archive: [NIIKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NIIKE.zip) (SHA-256: `4f79f9a62aed06db83f2965abcc42ca98ce5cc2128cebd15b50a46cfbb633dbe`)

## kex-08-1: The raw shared j-invariant is distinguishable from a uniform key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: NIIKE-lv128, -lv256, and -lv512 specification and reference API
Discovery: Moderate
Exploitation: Polynomial-time real-or-random distinguisher; no shared-key recovery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23
Follow-up source: [NIIKE team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VDKJZGVFIR4B7KO7QC75TKPBJJBWQKZ5/)

The specified `NIIKE.KeyAgr` (Algorithm 5, §4.3) returns the *unhashed* j-invariant of the shared supersingular curve. The submitted `kex_derive_ss_a/b` API likewise calls `niike_SecretAgreement` and serializes that field element directly with `fp2_encode`. An adversary given a candidate shared-key byte string can decode it as an element of Fp², construct a curve with that j-invariant, and test supersingularity. Every honest output passes. Only O(p) of the p² field elements are supersingular j-invariants, so a uniformly random canonical Fp² control passes with negligible probability. Uniform random API-length bytes are also distinguishable, even before the supersingularity test, because many are not canonical field encodings.

This is a polynomial-time real-or-random *key-distribution* break, not a method to compute the honest shared value from the public keys. It is a design error in the specified output, not an isogeny-path shortcut. The specification's §9.1.6 experiment samples its random branch from an abstract shared-key space `SK` without defining that space concretely. If `SK` were stipulated to be exactly the supersingular j-invariants with the honest distribution, this particular test would not distinguish that formal experiment. However, the proof of Theorem 9.1.7 explicitly analyzes a different construction that returns `H(K)` and compares it with a uniform hash output; Algorithm 5 and the shipped byte-key API perform no such hash. The submitted construction therefore fails the ordinary uniform-key indistinguishability target that its proof claims to establish. A primary key-exchange distinguishing break is Critical even without shared-key recovery.

The lv128 witness runs the official reference key generation and agreement for two honest parties, checks matching shared keys, then applies Sage's supersingularity test to the result and to 16 independently sampled *canonical* Fp² controls. It confirms an algebraic distinguisher independent of byte-encoding slack. The same raw-output data flow appears in all three levels; lv256/lv512 were not rerun in this witness because their reference group actions are much slower.

The NIIKE team acknowledges the implementation issue and states that the session key should be derived by applying a KDF to the key material.

### Proposed fixes

The team's response proposes applying a KDF to the shared key material and says an updated implementation will follow. This section records the proposal without evaluating it.

### Reproducing

Build the reference library and run the witness with Sage's Python:

```sh
make -C kex-08
mamba run -n sage python kex-08/reproduce_raw_key_distinguisher.py
```

The witness prints `ATTACK kex-08-1 NIIKE-lv128 CONFIRMED` when the honest key is supersingular and all controls are ordinary.
The command uses this host's Sage environment; elsewhere, any Python with `sage.all` importable can run the script.

## kex-08-2: NIIKE-lv512 key generation cycles between two hard-coded secret keys

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: NIIKE-lv512 reference and optimized implementations
Discovery: Trivial
Exploitation: At most two candidate private keys per party; shared-secret recovery from a public key requires at most two public-key comparisons and one agreement
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The lv512 `make_SecretKey` ignores its DRNG argument and copies one of two literal 759-entry secret vectors, selected by a global Boolean that toggles after each call (`NIIKE-lv512/protocols/bundleprotocols_internal.c:53-79`). The optimized helper is byte-identical. Both public-key entry points call this function (`ngccapi/KEX_AlgorithmInstance.c:59-80`). An attacker can precompute the two corresponding public keys and identify the private vector from any honest public key, then run the public agreement algorithm to obtain its shared secret. This is a complete key-space collapse in the submitted lv512 code, not a timing finding; lv128/lv256 use different key-generation helpers. The normal Makefile omits lv512 unless `NGCC_NIIKE_LV512=1`. Full lv512 public-key computation was not run here because the reference implementation estimates roughly a day per KAT record; the witness verifies the exact two-key cycle in the original helper.

### Reproducing

From the repository root, compile the original lv512 helper with section garbage collection so its unrelated, slow isogeny functions need not be linked:

```sh
ref='kex-08/Implementations and Test_Vectors/Implementations/Reference_Implementation'
tmp=$(mktemp -d)
cc -w -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types \
  -O2 -DRADIX_64 -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -I"$ref/NIIKE-lv512/ngccapi/include" -I"$ref/common/include" \
  -I"$ref/gf/include" -I"$ref/NIIKE-lv512/precomp/include" \
  -I"$ref/NIIKE-lv512/ec/include" -I"$ref/ec/include" \
  -I"$ref/NIIKE-lv512/protocols/include" -I"$ref/protocols/include" \
  kex-08/reproduce_lv512_two_keys.c \
  "$ref/NIIKE-lv512/protocols/bundleprotocols_internal.c" -o "$tmp/check_two_keys"
"$tmp/check_two_keys"
```

The witness prints `ATTACK kex-08-2 NIIKE-lv512 CONFIRMED: two-key cycle`.

## kex-08-3: A crafted peer key forces the honest party's shared secret

Severity: Medium
Status: Confirmed
Layer: Design
Affected: NIIKE-lv128 and NIIKE-lv256 reference implementations (shared source); demonstrated on lv128
Discovery: Moderate
Exploitation: The peer chooses its public key; no secret or computation beyond a public relabelling is needed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

The group-action design permits a peer to send a public relabelling of the honest party's own key (cycle reversed, `P` and `Q` swapped), producing a repeatable, non-contributory shared secret. Algorithms 5 and 9 do not require peer-key validation, while the specified HKR-CKS-1 model covers only honestly registered keys. A malicious NIKE peer already knows the shared secret, so this witness does not violate that model; it is a security-relevant contributiveness and key-derivation gap for unvalidated keys and is rated Medium, consistently with malicious-key override findings in KEMs. Separately, `kex_derive_ss_a`/`_b` accept all-zero or all-`0xFF` peer-key bytes and return an all-zero secret with success (`ngccapi/KEX_AlgorithmInstance.c:142,157`), an implementation input-validation defect.

### Reproducing

```sh
python3 kex-08/reproduce_malicious_peer_key.py
```

## kex-08-4: Malformed peer keys terminate the honest party's process

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: NIIKE-lv128 and NIIKE-lv256 reference implementations (shared source); demonstrated on lv128
Discovery: Trivial
Exploitation: One malformed peer public key aborts key derivation
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

Peer public keys are not validated before use. An honest key with its `P` and `Q` points swapped reaches the consistency check in `bundleeval_action_stra` (`protocols/bundleprotocols.c:193-213`), which aborts on `assert` in the submitted build; with `NDEBUG` defined the check, and with it the only validation, disappears entirely. A party deriving a key from an attacker-supplied, for example ephemeral, public key can thus be terminated.

### Reproducing

```sh
python3 kex-08/reproduce_malformed_key_abort.py
```

## kex-08-5: Malformed peer keys reveal static-exponent thresholds

Severity: Medium
Status: Confirmed
Layer: Design
Affected: NIIKE-lv128 reference implementation (run); NIIKE-lv256 shares the agreement source but was not run
Discovery: Moderate
Exploitation: One crafted peer key per query reveals whether one static exponent is below a chosen threshold; the demonstrated queries expose about 5.8 bits of a uniform lv128 key in expectation; no key recovery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

An NIIKE public key is a cycle of 13 tuples `(A24, P_s, P_t, Q_s, Q_t)` over F_{p^2}, where `P_s` and `Q_s` generate the two eigenlines used by the forward and backward ℓ_j-isogeny steps. `NIIKE.KeyAgr` (Algorithm 5, §4.3, physical p. 24) and `NIIKE.ModifiedKeyAgr` (Algorithm 9, physical p. 36) take the peer key as given, and the submitted `kex_derive_ss_a`/`_b` only decode it (`ngccapi/KEX_AlgorithmInstance.c:142,157`). In the first of the B = 35 iterations, step `t` for prime ℓ_j goes forward or backward according to `compare_gt(t, s[i])` on the victim's static exponent (`protocols/bundleprotocols.c:53`). The only consistency check is a j-invariant comparison inside `#ifndef NDEBUG` (`protocols/bundleprotocols.c:193–213`), which aborts on `assert` at line 205.

A malicious peer B takes its own honest key and, in every tuple, replaces `P_s` by `P_s + T`, where `T` is the point of order ℓ_j^m in `<Q_s>`. When the victim A derives a key from this crafted key, the hidden component is absorbed if `s_j ≥ m`, and A returns byte-for-byte the honest key `j([s_A][s_B]E_0)`, which B can compute itself. If `s_j < m`, the submitted assert build aborts with SIGABRT, and an NDEBUG build silently returns a different key. Any crash, key-confirmation failure or later MAC failure therefore answers the predicate `[s_j < m]` on A's long-term secret. For the 31 primes dividing p+1 this gives a zero test on every coordinate. On the 3^4 coordinate, orders 3, 9, 27 and 81 separate `s_0 = 0, 1, 2, 3` and `s_0 ≥ 4`; on the 11^2 coordinate, orders 11 and 121 separate `s_3 = 0, 1` and `s_3 ≥ 2`. The oracle exposes the first iteration's clipped exponent `min(s_j, e_j)`, since later iterations start from refreshed points (`R[0].Ps = R[1].Qs`, `protocols/bundleprotocols.c:234`). Secret exponents are uniform on `[0, B·e_j]`, so these queries expose about 5.77 bits of a uniform lv128 key in expectation. The 18 primes dividing p−1 need crafted twist points, which were not built. Extending the construction to them would raise this to about 9.06 bits. That extension is not part of this finding.

On a naturally generated lv128 victim, all 35 crafted queries matched the prediction: the three zero exponents aborted, and every other query returned the honest key exactly. A calibration on chosen exponent vectors reproduced each threshold exactly, and an NDEBUG rebuild gave the same predicate as a silent key mismatch. The specified HKR-CKS-1 experiment (§9.1, Definition 9.1.6, physical p. 55) is passive and uses only honestly generated keys, so this does not contradict the stated theorem. It is nevertheless a stable, secret-dependent reaction oracle on reused static keys through the submitted active API. No path from the leaked bits to key recovery is known, so it is rated Medium. lv256 uses the same `protocols/bundleprotocols.c`, but its group action takes about 10 minutes per operation and was not run.

### Reproducing

```sh
make -C kex-08
python3 kex-08/reproduce_exponent_reaction_oracle.py
NGCC_LONG=1 python3 kex-08/reproduce_exponent_reaction_oracle.py
```

The script checks the unguarded decode and the debug-only consistency check in the source, generates a victim and a peer with the submitted lv128 library, and uses Sage to craft 35 malformed peer keys from the honest peer key. It runs one natural victim on all 31 p+1 primes and the 9, 27, 81 and 121 thresholds, then a chosen-exponent calibration of the 3^4 and 11^2 thresholds. Controls are honest agreement in both directions and the exact honest key on every non-reacting query. It takes about 50 seconds on 28 cores (about 6 CPU-minutes) and exits 77 without Sage. `NGCC_LONG=1` adds three more natural victims and repeats everything on an NDEBUG build made in a temporary directory.
