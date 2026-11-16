<!-- synchronized report: kem-20/report.md -->
Candidate: MAMBA-Frost
Family: Lattice-based (learning with quantization)
Archive: [MAMBA-Frost.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/MAMBA-Frost.zip) (SHA-256: `ae363dbefd69d64e99987b64105d60bfa376d97c8b58b055665761559c44c78b`)

## kem-20-1: Fail-open key generation creates publicly decapsulatable keys

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All ten reference MAMBA-Frost and MAMBA-Frost-CC instances; optimized implementation excluded
Discovery: Moderate
Exploitation: An allocation failure during key generation returns success and makes every subsequently encapsulated shared secret recoverable from the public key; remote triggering is not demonstrated
Credit: Yamin Liu, with AI assistance
Date: 2026-10-04
Original source: [Liu's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XYDLYDGUCEQ6QPUCAL3T3RWJBIIGPDU4/)

Reference key generation calls `frost_mul_add_as_plus_e` to compute the public matrix product (`Frost/src/kem.c:262`). That function returns zero when its `N×N` `calloc` fails (`frost_macrify_reference.c:64–70`), but the caller ignores the result. Its zero-initialized `B_raw` is then packed into a public key corresponding to secret matrix `S = 0`, while the stored secret key still contains the sampled nonzero `S`, and key generation returns success.

Anyone with the faulty public key can build the accepting-path secret-key layout `[S=0 | pk | H(pk) | z]`; `z` is irrelevant when ciphertext verification succeeds. The all-zero packed matrix makes faulty public keys recognizable from their public bytes, so an observer can scan for them. Forced-allocation tests recover the sender's shared secret from ordinary ciphertexts in all ten reference instances, while decapsulation with the returned holder key fails. On this host, an ordinary `RLIMIT_AS` of 22–32 MiB reaches the same MAMBA-Frost-512 state without interposition or candidate-code changes. No remote method of forcing the allocation failure is claimed. The optimized implementation does not allocate this matrix and is excluded.

### Proposed fixes

The original post proposes checking the matrix-product return values and propagating pseudo-XOF failures, zeroizing partial outputs, and returning an API error on failure. This records the proposal without assessing it.

### Reproducing

```sh
make -C kem-20
python3 kem-20/reproduce_fail_open.py
python3 kem-20/reproduce_rlimit.py
```

The first witness interposes only the identified matrix allocation. For every reference instance it confirms that key generation reports success, the zero-secret layout recovers the encapsulated key, and the returned holder secret does not. It copies the stored `H(pk)` field from the holder key while using the remaining secret-key bytes only as a negative control; `H(pk)` is publicly computable from `pk`. The second witness uses util-linux `prlimit` and scans for the host-dependent address-space window in which the same fail-open state occurs without interposition.

## kem-20-2: Decapsulation branches on the sign bit of every secret coefficient

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: All ten MAMBA-Frost and Frost-CC parameter sets; reference, optimized and native implementations
Discovery: Trivial
Exploitation: Local branch trace of the secret matrix's sign pattern on every decapsulation; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

Decapsulation unpacks the secret matrix `S` and sign-extends each coefficient with a branch: `if ((S[i] & (1u << (PARAMS_SECRET_COEFF_BITS - 1u))) != 0u)` (`Frost/src/kem.c:492–496`). The loop runs over all coefficients on every call. `kem.c` is the same in every tree apart from banner and assertion macros. The specification requires implementations to "avoid secret-dependent branches and secret-dependent memory accesses" (§8.3, p. 20).

GCC 15.2 keeps the branch at `-O1`, `-O2`, `-O3` and `-Os`, and the harness-built libraries contain it (`test $0x4,%dl; je` in Frost-128, `test $0x2,%dl; je` in Frost-512). A branch-trace observer learns the sign bit of every coefficient. For the sets with coefficients in {−1, 0, 1} that is the exact set of −1 positions; for Frost-128 it is the set of negative coefficients. The pattern is fixed per key, so the observer is local. The resulting loss of lattice security was not quantified and no recovery was attempted.

Constant-time fix (easy, hence Low): sign-extend arithmetically, for example by XOR and subtraction of the sign-bit mask.

### Reproducing

```sh
make -C kem-20
objdump -d --no-show-raw-insn kem-20/lib/libMAMBA-Frost-128.so |
  awk '/<crypto_kem_dec[^>]*>:/{p=1} p' | grep -A1 'test   $0x4,%dl'
```

The output shows the test of the coefficient's sign bit followed by a conditional jump inside `crypto_kem_dec_Frost128`. This is a compiled-branch witness; no timing was measured.

## kem-20-3: A failed XOF makes the encapsulated key computable from the ciphertext

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All ten MAMBA-Frost and MAMBA-Frost-CC instances, reference and optimized implementations; the native SHAKE implementation is not affected
Discovery: Moderate
Exploitation: If one XOF allocation fails, encapsulation or decapsulation returns success with a shared secret computed from the ciphertext alone, or with an all-zero shared secret; no remote way to force the failure is shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; recovery witness by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-16
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/M65AQWRSK3S2AKWWKTNCLROB5XTWQG5U/)

`api_pseudo_xof` zeroes its output when the contest's `pseudoXOF` fails, but it returns `void` (`common/sha3/fips202.c:24–37`), so `shake` callers cannot see the failure. Three such calls in `Frost/src/kem.c` matter:

- `shake(G2out, ...)` at `:354` derives the noise seed `seedSE` and the key `k`. If it fails both are zero, the noise is expanded from a fixed seed, and the shared secret is `shake(ct ‖ 0)`.
- The final `shake(ss, ...)` in encapsulation at `:413` returns an all-zero shared secret.
- The final `shake(ss, ...)` in decapsulation at `:573` does the same for an honest ciphertext.

In every case the function returns 0. In all 20 trees, failing each of these allocations once gave a shared secret that the attacker recomputed from the ciphertext alone, while the honest party's key disagreed. Unfaulted controls round-trip.

These paths are separate from the key-generation `calloc` in this report and also affect the optimized trees. The failing allocation is a fixed-size buffer inside the contest helper. KEM input sizes are fixed, so a caller cannot choose it, and no remote way to force the failure is shown; memory pressure or a resource limit is needed. The candidate's defect is discarding the helper's status and returning success. A demonstrated session-key exposure under these preconditions is High.

### Reproducing

```sh
sh kem-20/reproduce_xof_zero_secret.sh
```

The witness wraps `malloc` to fail exactly the targeted allocation by its size and order and compares the returned key with the attacker's value.
