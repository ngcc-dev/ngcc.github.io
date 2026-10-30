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

The team initially stated that it would clarify the quantifiers and assumptions, revise the concrete DFR and failure-attack analysis, and investigate both worst-case and independent-key proof approaches. Its 2026-10-30 announcement says the revised specification now distinguishes average-case and worst-case failure probabilities and gives a revised concrete-security evaluation. These proposals and reported changes are recorded without evaluating the revised candidate.

### Reproducing

```sh
python3 kem-41/reproduce_dfr_model.py
```

The script is the model published with the forum post, parallelized and given
assertions for all six reported pairs. It labels the second result as a model
lower bound on the per-key worst-case DFR required by the cited reduction.
NumPy is required; the calculation is CPU intensive.

## kem-41-2: Key generation ignores XOF failure and can return decryption keys sampled from stale stack data

Severity: High
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

### Proposed fixes

The forum report proposes propagating XOF/hash failures through ZEN's samplers and KEM entry points, and not returning a key after an unwritten output is sampled. The ZEN team later announced that its revised x86 reference and AVX2 implementations fix the allocation-failure-induced uninitialized-memory issue; it says updates for the other platforms will follow. These proposals and reported changes are recorded without evaluating the revised implementations.

### Reproducing

```sh
sh kem-41/reproduce_keygen_fail_open.sh
```

The witness compiles each frozen reference tree with GCC `-O2` and no allocation interposition. It applies a 64 MiB address-space limit, retains ordinary small allocations, and checks public-only candidate selection, fresh decapsulation, a wrong-public-key control, and a normal-keygen control. It prints `CONFIRMED kem-41-2` for each level on the tested host. Stack overlap and the memory-exhaustion trigger can vary with build and host; an unsupported layout is reported as a skip.
