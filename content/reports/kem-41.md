<!-- synchronized report: kem-41/report.md -->
Candidate: ZEN
Family: Lattice (NTRU)
Archive: [ZEN.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/ZEN.zip) (SHA-256: `69eba070320fc6cb365fb6d43d2b74460487732aeb7e607fac2d6c1b3a64a80e`)

## kem-41-1: The numerical DFR model averages over messages while the proof assumes worst-case correctness

Severity: Medium
Status: Proof gap
Layer: Design
Affected: All ZEN parameter rows analyzed in Tables 2 and 3
Discovery: Moderate
Exploitation: Model lower bounds on the per-key worst-case failure probability exceed the averaged estimates, but no attack within 2^80 decapsulations is demonstrated
Credit: Leo Luo (archive sender `leoluo`)
Date: 2026-10-03
Original source: [Leo Luo's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LHS3HBDIJHUIDAKS5Q7H3FXGDY7CLNHZ/)
Follow-up source: [ZEN team's revised-version announcement](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AZGO7YMBSBRJNAY55767GRFQW652UQNB/)

Theorem 2 in §5.2 writes the PKE correctness error as
`delta_ZEN = max_m Pr[Decrypt(sk, Encrypt(pk,m,rho)) != m]`, with the
probability over key generation and encryption coins. The HHK17 and QROM
Fujisaki--Okamoto theorems cited there require the stronger per-key quantity
`E_sk[max_m Pr_rho[failure]]`, with the maximum inside the expectation over
keys. Thus the specification's displayed definition does not match the cited
theorems. The numerical model in §5.3 is weaker still: it assigns the message
coefficients an independent uniform binary distribution and therefore
averages over messages. Tables 2 and 3 use that model for the stated DFRs and
failure-attack margins.

The original post chooses each message bit as a function of three secret-key
coefficients. Such a per-key choice is admissible under the inner maximum
required by the cited theorems. Its script reproduces the specification's
averaged values and obtains much larger failure-model values, with gaps from
16.88 to 124.42 bits across the six rows. Those values are therefore model
lower bounds on the per-key worst-case quantity the reduction needs, rather
than merely diagnostics. They range from about `2^-104.69` to `2^-214.41`, so
even the largest still requires more than `2^80` decapsulations for an
expected failure. The result establishes a Medium proof gap, not a demonstrated
decryption-failure attack within the evaluation budget or a revised security
level.

### Follow-up Analysis

The [ZEN team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/7XCR7SE5QOJMFTS5WCNTKX7FA7M7P3TC/) agrees that the generic FO reduction's worst-case correctness notion and the concrete averaged failure behavior differ. It argues that locating a key-dependent bad message from the public key adds substantial work, and reports tighter classical/quantum failure-attack estimates above the three claimed levels even with a `2^80` online-query budget. Those new estimates were not independently reproduced here and do not repair the displayed theorem/model mismatch in the frozen submission, so the classification is unchanged.

In a [further exchange](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/7AZUGDUDXVOCOZWBZOKZY7VTONGO7KNH/), Leo Luo notes that the secret-key/message product in an NTRU construction makes the worst-case message quantifier especially relevant. The [ZEN team's detailed reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5NWIBJAG6GXLFAXULECPIB2XQVKMXOKQ/) explicitly accepts the frozen reduction/model gap and reports revised first-failure lower bounds above its targets, together with separate average-message, independent-key worst-case, and worst-case DFR estimates. We have not reproduced those revised estimates. They do not change the Medium proof-gap classification of the submitted analysis.

### Proposed fixes

The team initially stated that it would clarify the quantifiers and assumptions, revise the concrete DFR and failure-attack analysis, and investigate both worst-case and independent-key proof approaches. Its 2026-10-30 announcement points to the [revised ZEN v2.0 specification](https://light-lattice.org/zen/specifications/20261030/ZEN-20261030.pdf) and says it now distinguishes average-case and worst-case failure probabilities. In a [2026-10-31 follow-up](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3WCO47NOVLIYELKUXDNSB76LPXEAD3VU/), Leo Luo questions the revised worst-case DFRs (`2^-100`, `2^-127`, `2^-106`) and proposes a shifted-Gaussian failure-attack model giving 109, 176 and 138 security bits; he explicitly says the model's suitability remains unresolved and requests the team's derivation. This concerns the revised version only. Neither the revision nor that attack model has been evaluated here; the frozen-version classification is unchanged. In its [2026-11-11 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QWJ7PMZKR3SKJNU2DEK6HSBVQDQLVKB5/), the team accepts that messages may correlate with the secret key. It announces, for the next revision, an asymptotic reduction for messages chosen efficiently from the public key, and more conservative parameter sets; neither is available for evaluation.

### Reproducing

```sh
python3 kem-41/reproduce_dfr_model.py
```

The script is the model published with the forum post, parallelized and given
assertions for all six reported pairs. It labels the second result as a model
lower bound on the per-key worst-case DFR required by the cited reduction.
NumPy is required; the calculation is CPU intensive.

## kem-41-2: Key generation ignores XOF failure and can return decryption keys sampled from stale stack data

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: ZEN-128, ZEN-256 and ZEN-512 reference implementations; optimized variants have the same error-discarding path by source inspection but were not run
Discovery: Moderate
Exploitation: Address-space exhaustion can make key generation sample an unwritten stack buffer; the demonstrated same-thread public-data call sequence permits decryption-key recovery, but no remote trigger or affected deployment is demonstrated
Credit: harry0597 (NGCC PKC Forum sender; signed Hui Wen and XingYu Wu), with DeepSeek assistance
Date: 2026-10-22
Original source: [Hui Wen and XingYu Wu's PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MDKAVOLOV5VMHHZXAWCWGQTOBIQUB7B7/)
Follow-up source: [Correction of the ZEN-128 encapsulation claim](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XS5NSYQB2IES2J4Y4FDKFBXOFL6I5CKN/) and [ZEN team's revised-version announcement](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AZGO7YMBSBRJNAY55767GRFQW652UQNB/)

The supplied `pseudoXOF` returns an error without writing its output when an allocation fails (`auxfunc.c:482–498`). ZEN's `void zen_pseudoXOF` discards that return (`symmetric.c:13–22`), and `poly_generate_f` or `poly_generate_gf` samples the unwritten stack buffer (`poly.c:311–317` at 128, `:393–399` at 256, `:640–646` at 512). Key generation neither propagates the error nor rejects the resulting key (`pke.c:19–80`; `KEM_AlgorithmInstance.c:80–101` in the 128-bit reference tree, with corresponding paths at the other levels). The general defect is secret sampling from uninitialized memory; public recovery is the demonstrated case, when a preceding operation in the same thread leaves public-key data in that stack area. The flaw is in ZEN's error handling, not the placeholder XOF's cryptographic strength; any replacement that can fail without filling its output requires that error to be handled.

In an independent `-O2` reference build, a 64 MiB `RLIMIT_AS` and retained allocations caused real XOF allocation failures without interposition or candidate-code changes. The witness generates the preceding public key and the faulted key in one process and thread, with a public-key encryption in between to exercise the stack-reuse path. At all three levels, `kem_keygen` nevertheless returned success. A scan using only the preceding public key and the newly returned public key selected the decryption polynomial through the public relation `h·f = g` with small `g`. A key assembled from that polynomial, the returned public key, and a recomputed `H(pk)` decapsulated a fresh honest ciphertext to the sender's shared secret. The true decryption-secret prefix matched only as a final control; a wrong preceding public key and a normal key generation yielded no selected candidates. At ZEN-512, an additional failed allocation left the holder's stored `H(pk)` unwritten, so the returned holder key itself did **not** match the sender, while the publicly reconstructed key did. In a separate 24-seed ZEN-128 sweep, a counting-only allocation wrapper delegated every request to real `malloc`: 11 key generations returned vulnerable keys and 13 entered a retry loop. Smaller 256/512 sweeps also observed both outcomes. These are build- and memory-state-dependent observations, not a demonstrated way to exhaust a remote service.

The same unchecked wrapper also makes encapsulation return success after an XOF failure. We independently observed seed-independent faulted ZEN-128 PKE ciphertexts and a KEM shared-secret mismatch, but did **not** independently attempt the forum's plaintext or sender-session-key recovery from faulted encapsulations. The key-generation witness covers the primary consequence at all three levels.

Reclassified from High to Medium on 2026-11-23. In the demonstrated call sequence anyone can recover the faulted key from public data, but the failing allocation is inside the contest's provisional `pseudoXOF`, which a replacement need not have, and the attacker cannot cause the failure.

### Proposed fixes

The forum report proposes propagating XOF/hash failures through ZEN's samplers and KEM entry points, and not returning a key after an unwritten output is sampled. The ZEN team later announced that its [2026-10-30 v2.0 implementation package](https://light-lattice.org/zen/implementations/20261030/ZEN-20261030.zip) fixes the allocation-failure-induced uninitialized-memory issue in the x86 reference and AVX2 implementations; it says updates for the other platforms will follow. This is a pointer to the team's revision, not an evaluation of it; the frozen-version finding remains unchanged.

### Reproducing

```sh
sh kem-41/reproduce_keygen_fail_open.sh
```

The witness compiles each frozen reference tree with GCC `-O2` and no allocation interposition. It applies a 64 MiB address-space limit, retains ordinary small allocations, and checks public-only candidate selection, fresh decapsulation, a wrong-public-key control, and a normal-keygen control. It prints `CONFIRMED kem-41-2` for each level on the tested host. Stack overlap and the memory-exhaustion trigger can vary with build and host; an unsupported layout is reported as a skip.

## kem-41-3: Decoding stores each bit at a secret-selected address

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: ZEN_128, ZEN_256 and ZEN_512; reference and AVX2 implementations
Discovery: Moderate
Exploitation: Local address trace of one comparison bit per coefficient group on every decapsulation; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15
`pke_dec` computes its simple decoding with masks, but uses the last comparison to choose where to write: `idx = (i & (-mask)) | ((i + ZEN_N4) & (~(-mask)))` followed by `t2[idx] = t1[i] & 1` (`pke.c:185–186` in reference ZEN_128; the other levels and the AVX2 tree have the same statements). The comparison is between distances computed from the ciphertext and the private key, so the address of each store is a secret-dependent choice between two locations a quarter of the ring apart.

An address-trace observer learns one comparison bit per group for every ciphertext it submits, before the validity decision. Key generation also reads an inverse table at an index formed from secret values (`ntt.c:341`). The specification describes the implementation as constant-time and validated with a dynamic tool. No oracle or recovery was built.

Constant-time fix (easy, hence Low): write both slots with masked values.

### Reproducing

```sh
sed -n '183,186p' kem-41/Implementations/Reference_Implementation/ZEN_128/pke.c
```

This is a source witness.

## kem-41-4: A weak-key failure search over 2^80 ZEN-512 public keys is estimated at 2^354

Severity: High
Status: Lead
Layer: Design
Affected: ZEN-512 parameters; the other rows were not analysed
Discovery: Non-trivial
Exploitation: Estimated 2^354.5 work for one decryption failure among 2^80 public keys, with 2^80 decapsulations per key; no failure was produced and no key recovery is shown
Credit: Chenyi Li, with GPT assistance
Date: 2026-11-26
Original source: [Chenyi Li's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/YSXCHC7DBSV436HRPINO5YL2UHOOUCJY/)

Table 2 (physical p. 24) prices a decryption-failure attack on ZEN-512 at 2^748.4 classical operations within 2^80 queries, counting one failure as success, for one key and uniform messages. Decryption works on `τ(g·s + f·U) + κ·f·m` before reduction modulo `q`, where `U` is the encryption error plus the compression error and, in blocks of four coefficients, `τ = 1 + Y²` and `κ = Y² + Y³` (§5.3). A message bit set to one thus adds `f2 + 2·f3 + f4` of its paired block of `f` to a sum that the failure bound of §5.3 compares with `q = 769`.

The post fixes 212 message bits to one and draws the other 300 at random. A key is weak when at least 34 of the 212 paired blocks have `f2 + 2·f3 + f4 ≥ 3`, which adds at least 102 to that sum; this has probability 2^-78.5. The attacker keeps a candidate ciphertext only if two squared norms of its own randomness, compression error and message pass thresholds. A fraction 2^-194.5 pass, and a kept candidate fails with probability 2^-80.0 on average over weak keys: one expected failure for 2^274.5 candidate encryptions and 2^80 decapsulations. Weak keys cannot be recognised, so the search runs on each of 2^80 public keys, about 2.8 of them weak, for 2^354.5 work against the 512-bit target. The post's quantum figure, 2^257.2, is above the 256-bit target.

The witness recomputes the post's figures to six decimals with its own enumeration. With the exact law of the `g·s` term in place of the post's Gaussian approximation, the failure probability is 2^-79.85. The limits are:

- **Query count.** The search makes 2^160 decapsulations, against an evaluation budget of 2^80. On a key drawn at random the same search fails with probability 2^-123.9, and a screen that 2^-843 of candidates pass still gives 2^-83.7, so the figure needs the key pool.
- **Average rate.** The failure probability is an average over weak keys; its spread over single keys was not computed.
- **Model.** Compression errors are taken as independent, with the law of a uniform input. The tested event is one that the specification's bound counts as a failure; the decoder was not run.
- **Outcome.** No failure was produced. One failure is the specification's own success criterion (§5.5), and no key recovery from failures is shown.

Hence High / Lead: the figure is not a below-target attack within the evaluation budget.

### Reproducing

```sh
python3 kem-41/reproduce_failure_search.py
```

The script needs NumPy and about 1 GB of memory and runs in about two minutes. It is an independent implementation that confirms the post's arithmetic in the post's model. The post's archive, `Zen-computation.zip`, was not downloaded or run.
