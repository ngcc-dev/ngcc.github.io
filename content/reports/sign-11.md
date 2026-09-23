<!-- synchronized report: sign-11/report.md -->
Candidate: FlexTree
Family: Hash-based (stateless)
Archive: [Flextree.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Flextree.zip) (SHA-256: `f31d434ac297ef6a8c454bf9d219f125290749de157df3eb90d29ae3b8a0270a`)

## sign-11-1: PORS counter grinding reduces every claimed security level

Severity: High
Status: Confirmed
Layer: Design
Affected: All eight parameter sets
Discovery: Moderate
Exploitation: Approximately 2^134 to 2^489 work after 2^64 signing queries
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

FlexTree first derives the PORS instance from `HMSG(R, PK.seed, PK.root, msg)`, then searches a 32-bit counter in `HPORS(R, ctr, md)` until the selected subset passes forced pruning. Verification accepts any successful counter. An attacker can therefore keep the instance fixed while trying up to `2^32-1` different subsets, whereas the submitted bound models every trial as selecting a fresh random instance.

At the unstated `q_sig = 2^64` budget that reproduces the specification's security table, an independent evaluation of the paper's raw attack gives 133.1, 128.9, 225.2, 224.2, 352.2, 352.0, 480.0, and 480.0 bits for the 160s through 512f sets. Accounting for repeated leaves and the forced-pruning condition raises these estimates but still leaves the claims overstated by approximately 20 to 32 bits.

The repair is to bind the counter into the hash that selects the PORS instance, or require and verify the unique minimal acceptable counter.

### Reproducing

```sh
python3 security/flextree_kudinov_validation.py
```

## sign-11-2: Withdrawn — SM3 evaluation-mode length extension

Severity: Info
Status: Withdrawn
Layer: Evaluation
Affected: Concrete SM3 evaluation instantiation of the deterministic option only
Discovery: Moderate
Exploitation: None under the ideal-primitive model
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

Kudinov observed that the concrete secret-prefix SM3 evaluation function is length-extendable in deterministic mode. However, the FlexTree specification's page-45 warning explicitly treats the Section 1.3 SM3-derived functions as ideal stand-ins and excludes Merkle–Damgård flaws from its security claim. An ideal replacement with the same interface and output length does not reveal a chaining state, so the proposed predictable-randomizer attack does not apply. The shipped signer also uses fresh `optRand`. This ID is retained to record the withdrawal, not as an active vulnerability.

### Reproducing

```sh
python3 security/flextree_kudinov_validation.py
```

The script checks the concrete evaluation construction and hedged-only code path;
it is not a witness against an ideal replacement.

## sign-11-3: The specified OTS verifier omits its encoding checks

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Specification-conformant verifiers, all parameter sets; submitted verifier is unaffected
Discovery: Trivial
Exploitation: About 2^40.4 work for a full FlexTree-160s forgery
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

Algorithm 9 accepts an OTS digest only when its leading `zb` bits are zero and its digit vector has the required constant sum. Algorithm 10 and the abstract verifier in Construction 1 recompute the digits but enforce neither condition. Without those checks, the claimed incomparable encoding becomes an ordinary checksum-free Winternitz encoding.

Given one OTS signature with digits `x`, an attacker searches for a target digest whose digits `x'` satisfy `x' >= x` componentwise, then advances every disclosed chain by `x'-x`. Independent generating-function calculations reproduce Kudinov's per-trial costs of `2^33.35` through `2^128` for all eight specified parameter sets. Reusing the top XMSS signature and freely choosing the lower signature material adds the seven-bit top-layer leaf match for FlexTree-160s, giving about `2^(33.35+7) = 2^40.4` work. The analogous estimate for 160f is about `2^(47.25+3) = 2^50.3`.

The submitted `wots_pk_from_sig` does perform both checks, so existing binaries are not affected. The normative verifier must explicitly enforce the zero-bit and constant-sum conditions.

### Reproducing

```sh
python3 security/flextree_kudinov_validation.py
```

## sign-11-4: Withdrawn — SM3 evaluation-state ceiling

Severity: Info
Status: Withdrawn
Layer: Evaluation
Affected: Concrete SM3 evaluation instantiations of FlexTree-384s/f and FlexTree-512s/f only
Discovery: Trivial
Exploitation: None under the ideal-primitive model
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

The concrete counter-mode SM3 evaluation XOF has a 256-bit internal state regardless of output length. But the specification's page-45 warning explicitly acknowledges this limitation and assumes ideal Section 1.3 functions with the specified external dimensions instead. The internal-state ceiling does not carry over to such a replacement. This ID is retained to record the withdrawal, not as an active vulnerability or a claim that fixed output dimensions alone meet every advertised security level.

### Reproducing

```sh
python3 security/flextree_kudinov_validation.py
```

The script checks the concrete evaluation construction and parameter widths;
it is not a witness against an ideal replacement.

## sign-11-5: Unchecked PORS padding makes signatures malleable

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All parameter sets
Discovery: Trivial
Exploitation: Trivial from one valid signature
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

PORS signatures reserve space for `mMAX` authentication nodes and zero-pad the unused suffix. The verifier recomputes the actual node count and reads only those nodes; neither the specification nor the implementation requires the remaining bytes to be zero. Whenever padding is present, it can be changed freely without invalidating the signature.

The existing 160f harness result is a direct witness: flipping bit 28911 at byte 3613 yields a byte-distinct signature that verifies for the same message and key. Source inspection places that byte in the unused PORS authentication-node suffix. This does not forge a new message and no explicit SUF-CMA claim was found, but it defeats canonical signatures and can break protocols that use a signature or its hash as an identifier.

### Reproducing

```sh
make -C sign-11 lib/libFlextree-160f.so
make -C tools
tools/ngcc_attack sig-pors-padding sign-11/lib/libFlextree-160f.so
```

## sign-11-6: The specified PORS tree reuses leaf hash addresses

Severity: Low
Status: Confirmed
Layer: Design
Affected: Specification-conformant implementations; submitted code is unaffected
Discovery: Trivial
Exploitation: One-bit generic multi-target loss and interoperability failure
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

Algorithms 17 and 21 hash a height-1 PORS leaf for secret index `i+s` with `(treeHeight=0, treeIndex=i)`. The same tweak is already used for height-0 leaf `i`, contrary to the specification's distinct-address requirement. Depending on the set, 516 to 95,017 tweaks per instance are reused for two independent secret values.

The collision gives a one-bit generic multi-target advantage on that leaf-preimage path and invalidates the distinct-tweak premise invoked by the security discussion. It also prevents interoperability: the submitted code correctly uses global leaf index `i+s`, so a literal implementation of the algorithms computes a different PORS root whenever a height-1 leaf is revealed. Both algorithms should use `setTreeIndex(i+s)`.

### Reproducing

```sh
python3 security/flextree_kudinov_validation.py
```

The `reused-addresses` column recomputes the collision count for every set.

## sign-11-7: The implementation leaves 1 to 4 OTS digest bits unchecked

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Seven parameter sets; FlexTree-384s has no loss
Discovery: Trivial
Exploitation: Exact 1- to 4-bit reduction on the OTS digest path
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

The code derives OTS digits from the leading `8n-zb` digest bits but tests the high `zb` bits of the final byte. Those regions overlap for seven sets, leaving an equal number of other bits neither encoded nor checked. The effective matched lengths are 157, 159, 252, 255, 384, 382, 511, and 509 bits for 160s through 512f: losses of 3, 1, 4, 1, 0, 2, 1, and 3 bits.

This is not the best known attack because `sign-11-1` is cheaper, and injectivity is not lost. It is nevertheless a concrete implementation-level shortfall from the claimed `8n`-bit OTS digest path. The verifier must check exactly the `zb` bits excluded from digit decoding.

### Reproducing

```sh
python3 security/flextree_kudinov_validation.py
```

## sign-11-8: Complementary constant-sum rounding breaks interoperability

Severity: Low
Status: Confirmed
Layer: Design
Affected: FlexTree-384f and FlexTree-512s specification/code interoperability
Discovery: Trivial
Exploitation: Deterministic interoperability failure; no security loss from the rounding alone
Credit: Mikhail Kudinov <mishel.kudinov@gmail.com>
Date: 2026-09-22

Algorithm 9, the Section 1.7 prose, and Construction 1 explicitly require the OTS digit sum to be `floor(sum_i(w_i-1)/2)`. The specified signer therefore terminates. For FlexTree-384f and FlexTree-512s, those digit sums are 1169 and 1565.

The code's `chain_lengths` instead computes the complementary sum `sum_i(w_i-1-x_i)` and compares it with `WANTED_CHECKSUM` values 1169 and 1565. Consequently, the code accepts digit sums 1170 and 1566, the ceilings rather than the specified floors. A specification-conformant implementation and the submitted implementation therefore reject each other's OTS signatures for these two sets.

The specification also leaves a “valid counter” predicate undefined, uses non-integral byte slices, disagrees with its tables about the `HPORS` argument order, and differs from the code's digit window and compressed-address encoding. These are additional interoperability defects, but the previously reported non-termination claim was incorrect.

### Reproducing

```sh
python3 security/flextree_kudinov_validation.py
```
