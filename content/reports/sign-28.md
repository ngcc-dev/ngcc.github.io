<!-- synchronized report: sign-28/report.md -->
Candidate: SYDO
Family: Code-based signature (syndrome decoding, MPC-in-the-head)
Archive: [SYDO.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/SYDO.zip) (SHA-256: `c4ae5b27a188612cd286a786179ce5461e6aca0b8599ba13b8d77b210a940adb`)

## sign-28-1: SYDO enforces two fewer grinding bits than its claimed soundness

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All six 160-, 256- and 512-bit parameter sets, reference and optimized implementations
Discovery: Non-trivial
Exploitation: Generic QuickSilver forgery work about 2^158, 2^254 or 2^510 hash calls; the 256- and 512-bit sets miss their NGCC targets
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HMZS3BAVGCFDQRAQKQU3UZ7DZT7EF524/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/709d5ec64239206effb2667ca853ddcef3c060b4/sydo-grinding-and-padding)

Section 5.2 requires `tau*log2(N) - log2(d) + wgrind >= lambda`, with `d=4`, and Table 5.3 takes equality. Consequently `tau*log2(N) + wgrind = lambda+2`. Algorithms 2 and 3 nevertheless divide a `lambda`-bit `chall3` into `wgrind` checked zero bits and only `lambda-wgrind` bits for `VOLE.DecodeAllChall`, whose specified input needs `tau*log2(N) = lambda-wgrind+2` bits. This two-bit type mismatch holds by construction at all six parameter sets.

Both submitted implementations resolve the mismatch by making `delta_bits = lambda-wgrind+2` and checking only the remaining `wgrind-2` bits for zero. The shipped signatures corroborate the implementation behavior: only 13 of 60 KATs satisfy the specification's full grinding predicate, and their counters match two fewer enforced bits. A degree-four QuickSilver false witness can select four accepting challenge values, so the realized challenge space gives about `2^(lambda-2)` forgery work: `2^158`, `2^254`, and `2^510`. The 160-bit sets remain above the NGCC 128-bit floor, but the 256- and 512-bit sets miss their applicable 256- and 512-bit targets; Theorem 25's own bound is already only about 157.0, 254.3, and 509.9 bits. The reported margins are only two bits and count hash calls rather than a normalized end-to-end gate cost, so a sufficiently expensive trial implementation could close them; the classification applies the policy's strict below-target rule to the stated hash-call model. This is Critical under that rule even though the full-size searches are computationally infeasible. The forum authors do not claim a practical break. The public package verifies the four-root strategy in a scaled exact field model; the full-size searches are not attempted.

### Proposed fixes

The original post proposes lengthening `chall3` by `ceil(log2(d))` bits, increasing every `wgrind` by two, or lowering the stated target by two bits and correcting the parameter tables. This section records those alternatives without evaluating them.

The [team's 2026-10-09 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XT4KSQWTVAZYTA2XG6EUWZATACTHSLAV/) says it revised the grinding table to match the code and counts bit operations per hash evaluation when assessing the security margin. This records its position without evaluating the revision or changing the frozen-submission classification.

### Reproducing

```sh
./sign-28/reproduce_forum_findings.sh
```

The wrapper verifies and unpacks the archived submission, fetches the pinned public package, builds all six reference sets, reads the enforced-bit counts through the submitted library's accessors, checks the KAT predicates and counters, and runs the exact scaled QuickSilver control.

## sign-28-2: The reference verifier ignores required BAVC opening padding

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: All six reference parameter sets; the optimized implementations reject the same mutations
Discovery: Trivial
Exploitation: Same-message signature malleability and cross-implementation verifier disagreement; no new-message forgery
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HMZS3BAVGCFDQRAQKQU3UZ7DZT7EF524/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/709d5ec64239206effb2667ca853ddcef3c060b4/sydo-grinding-and-padding)

Algorithm 13 lines 21–22 require the unused tail of the fixed-size BAVC opening to be all zero. The optimized verifier checks every remaining byte in `vector_com.inc:994–1002`; the reference `sydo_ref_bavc_verify` reaches `ok = true` at `bavc_impl.inc:446` without inspecting that tail.

Across three signatures at every parameter set, 16 signatures had nonempty padding. Replacing the complete zero tail with `0xA5` was accepted by the reference verifier in all 16 cases and rejected by the optimized verifier in all 16. A bounded 160f bit-flip sweep found precisely the 1,120 accepted flips expected from its 140-byte padding and no optimized acceptance. SYDO does not claim strong unforgeability, so this is not presented as an EUF-CMA break; the security-relevant result is malleability plus incompatible verdicts on an identical signature.

### Proposed fixes

The original post proposes checking every remaining byte of the fixed-size opening before the reference verifier returns success. This section records the proposal without evaluating it.

The [team says](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XT4KSQWTVAZYTA2XG6EUWZATACTHSLAV/) it added that check in its development version. The revision has not been evaluated here.

### Reproducing

```sh
SETS=160f ./sign-28/reproduce_forum_findings.sh full
```

This cross-verifies three mutated signatures and runs the bounded bit-flip control against both submitted trees. It takes about ten minutes on the reporting host; remove `SETS=160f` to repeat the cross-verification at all six sets.

## sign-28-3: The implementations omit the Hash4 step required by the proof

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: All six parameter sets, reference and optimized implementations
Discovery: Moderate
Exploitation: The implementation is outside the stated extraction proof; no concrete forgery demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HMZS3BAVGCFDQRAQKQU3UZ7DZT7EF524/)

Algorithms 2 and 3 derive `iv = Hash4(ivpre)`, carry `ivpre` in the signature, and let the Lemma 19 extractor program `Hash4`. Both implementation trees instead derive `seed || iv` directly with the domain-three hash, serialize `iv`, and feed it directly to reconstruction. There is no candidate `Hash4` call or domain-four hash in either implementation.

The shipped construction is therefore not the construction covered by the stated binding and EUF-KO extraction argument: its `iv` is supplied directly by the signature rather than constrained to be a `Hash4` output. A verifier implemented literally from the specification also disagrees with the shipped KATs. No practical attack from this proof mismatch is claimed.

### Proposed fixes

The [team says](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XT4KSQWTVAZYTA2XG6EUWZATACTHSLAV/) its development versions now compute `iv=Hash4(ivpre)` and include `ivpre` in the signature. This is recorded without evaluating the revision.

### Reproducing

```sh
python3 sign-28/reproduce_static_findings.py
```

The source/specification validator checks the normative `Hash4` steps and extractor dependency, then checks the direct serialization and use of `iv` in representative reference and optimized sources.

## sign-28-4: Reference universal hashing reads beyond an eight-byte stack buffer

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All six reference parameter sets during honest signing and verification
Discovery: Trivial
Exploitation: Out-of-bounds stack read and undefined behavior; no disclosure, forgery, or control-flow impact demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HMZS3BAVGCFDQRAQKQU3UZ7DZT7EF524/)

`universal_hashing_impl.inc:447–452` declares `uint8_t tmp[8]` but sets `left = lambda_bytes-byte_off`, passes that value to the partial store, and then reads `tmp[j]` for every `j < left`. On the first word, `left` is 20, 32, or 64 bytes, so ordinary signing and verification read well past the eight-byte object. Later iterations replace the affected output, which explains why the KATs still match, but does not make the access defined. No attacker-controlled disclosure is established.

### Proposed fixes

The original post proposes clamping each processed chunk to eight bytes. This section records the proposal without evaluating it.

The [team says](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XT4KSQWTVAZYTA2XG6EUWZATACTHSLAV/) its development version fixes the over-read. That revision has not been evaluated here.

### Reproducing

```sh
python3 sign-28/reproduce_static_findings.py
```

The validator checks the identical faulty loop in all six reference trees and confirms that the supported security-parameter byte lengths all exceed eight.

## sign-28-5: An undocumented exported helper generates keys from a public constant

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Undocumented `sydo_ref_keygen` and `sydo_ref_sign` helpers in all six reference source trees; submitted NGCC APIs are unaffected
Discovery: Trivial
Exploitation: Trivial reproduction of every key generated through the helper; no submitted API path reaches it
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Sun Shuzhou's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/HWARV6IQNFUCAC5OHNURHPKIDNTXTJCQ/)

The exported helper `sydo_ref_keygen` obtains its seed from `rand_bytes` (`sydo.c:645–657`). In every reference tree, `rand_bytes` initializes a static DRBG once with the public 55-byte string `0xA5 XOR i` and never reads operating-system entropy (`randomness.c:10–31`). The first key pair is therefore identical in every fresh process, and the later stream is also publicly computable. The related `sydo_ref_sign` helper uses the same generator (`sydo.c:887–902`). This contradicts Algorithm 1's random `seed_sk` and `seed_pk` and permits complete signing-key reproduction if the helper is used.

Nothing in the submitted trees calls these helpers, they are documented only by declarations in `sydo.h`, and the package does not build a library exposing them. The submitted NGCC `sig_keygen` adapter instead draws an explicit seed from the framework DRNG and calls `sydo_ref_keygen_from_seed`; the optimized path also uses proper entropy. Because the cryptographic failure is confined to unused, undocumented source helpers rather than the candidate API, the finding is Medium rather than Critical.

The helper must obtain cryptographic entropy from the operating system or require a caller-supplied seed through an explicit deterministic interface.

### Proposed fixes

The [team says](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FQP7NYC4OIBY4KGMUL5ZZQMNX4RVLPLJ/) it removed the unused helpers and fixed-seed generator from its forthcoming update. This records the proposal without evaluating the revised implementation.

### Reproducing

```sh
make -C sign-28 reproduce-fixed-rng
```

The witness builds the unmodified SYDO-160s reference core, invokes the helper in two fresh processes, and requires byte-identical public and secret keys. It also checks that the optimized randomness source contains an operating-system entropy path as a scope control.
