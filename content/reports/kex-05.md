<!-- synchronized report: kex-05/report.md -->
Candidate: Loom
Family: Hybrid lattice KEM/signature AKE
Archive: [Loom.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Loom.zip) (SHA-256: `e9e7ff0fb453a371634797febeaeac7c1f081b5fd2438204787c763667482ec4`)

## kex-05-1: The specified decryption-failure rate causes honest-session aborts

Severity: Low
Status: Confirmed
Layer: Design
Affected: LoomKEX-256 construction and submitted reference implementation
Discovery: Non-trivial
Exploitation: Observable honest-session abort at the specified rate; no confidentiality, authentication, or key-recovery consequence
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The Loom specification states a decryption-failure rate of `2^-18.9` for LoomKEX-256 (Table 4, physical PDF page 17) and chooses it deliberately to keep first-flight messages below common MTUs (§1.1, pages 3–5). Its four-pass AKE treats rigid KEM decapsulation failure as a protocol abort, to be handled by a protocol-level retry, rather than recovering internally. The NGCC call sets no numeric failure-rate threshold; it requires an analysis of the failure probability and its security impact ([Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf) §3.3.2(3)), which the specification provides.

A deterministic whole-scheme search found such an abort at global trial index `136129`. Both parties generate honest long-term keys, pass 1 produces 1,352 bytes, and pass 2 produces 1,384 bytes. The initiator's `kex_generate_pass3_msg_a` then returns `-3` because it cannot decapsulate the responder's honestly generated KEM ciphertext. Messages 3 and 4 remain absent and neither party produces a shared secret.

The submitted scalar reference implementation reproduces the recorded seed, keys, states, pass-1/pass-2 messages, failure stage, and return code exactly. The separately submitted optimized implementation produces the same transcript and failure, but it is not required to reproduce this finding.

This confirms the specified correctness/bandwidth trade-off in the submitted code: honest sessions abort at the stated rate. It is a reliability property, not a confidentiality, authentication, or key-recovery result, hence Low.

The complete witness is `security/loom256_failure_witness.txt`; its SHA-256 digest is `b957dac32f2b3dfd0e689c0ea47bf7281cdc1bebbf48303e491be052a9067168`.

### Reproducing

Build the submitted scalar reference implementation and replay only the known witness index:

```sh
make -C kex-05 replay
kex-05/reproduce_failure 136129 1 1 /tmp/loom-witness.txt 0
sha256sum /tmp/loom-witness.txt
```

The replay reports `stage=pass3 code=-3`. The generated reference witness differs from the retained optimized witness only in its `implementation=` metadata line; all cryptographic and protocol fields are byte-identical. The longer deterministic search procedure and cross-check are documented in `security/LOOM_FAILURE_SEARCH.md`.

## kex-05-2: Ephemeral-key reuse recovers the complete Loom-KEM secret key

Severity: High
Status: Confirmed
Layer: Design
Affected: LoomKEX-256 construction; demonstrated with the reference and optimized implementations
Discovery: Non-trivial
Exploitation: 4,532 pass-2 messages processed under one pass-1 state in the deterministic witness; requires reuse of the ephemeral key, which the specification excludes
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Loom team's 2026-09-29 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/IYWTI3KKQX26OFA7AGT5OJ7L6D5UWUQ2/)

Loom's ephemeral KEM is IND-CPAF secure: it tolerates the adversary observing at most one decapsulation-failure event per key pair (pages 4 and 20), and it omits the Fujisaki–Okamoto re-encryption check. The specification states that the KEM "is intended only for strictly ephemeral use and is not claimed to be secure under static or reused decapsulation keys" (page 33), and its CK-model proof assumes single use. The NGCC evaluation nevertheless takes "security in the case of (temporary) key reuse" into consideration ([Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/tT7TSQiz.pdf) §1(3)). This finding quantifies that property: if one pass-1 state processes many chosen pass-2 messages, the ephemeral secret is recovered completely.

Loom itself describes the mechanism in §4.4 (physical PDF page 48): reuse exposes an explicit failure oracle, and the text warns that established failure-boundary techniques can recover the reused decapsulation key. The contribution here is a concrete whole-scheme recovery for the submitted LoomKEX-256 implementation, requiring 4,532 chosen pass-2 queries in the deterministic witness.

The attack uses tagged Loom-KEM ciphertexts whose message is known and whose `u` component contains one sparse coefficient. It places one `v` coefficient exactly at the message-decoder boundary. Pass 3 emits a message precisely when the corresponding signed secret coefficient lies on the selected side of that boundary. Two probes identify whether each coefficient is positive, negative, or zero; three further threshold probes recover the magnitude of every nonzero CBD-8 coefficient in `{1,...,8}`. The remaining output coefficients are placed safely within the expected decoding region, so each answer isolates the intended coefficient.

The deterministic run recovers all 1,024 coefficients of the four-polynomial ephemeral secret after 4,532 complete `kex_generate_pass3_msg_a` calls. The recovered key decapsulates an independently generated honest pass-2 ciphertext. The witness then completes honest passes 3 and 4 and derives both parties' shared secrets; applying Loom's KDF to the recovered KEM key produces the identical 32-byte AKE shared secret. The submitted scalar and AVX2 implementations reproduce the same recovered-key digest, query counts, transcript result, and shared secret. With `LOOM_ATTACK_SEED_TWEAK=0` through `7`, all eight independently generated ephemeral keys were recovered and all eight completed-session secrets matched; query counts ranged from 4,481 to 4,592.

The witness reuses the key by restoring a saved copy of the serialized pass-1 state before each query; the NGCC key-exchange API keeps that state in a caller-held buffer for every multi-pass submission. A deployment that consumes each pass-1 state exactly once is not affected. The result shows that Loom provides no security under temporary ephemeral-key reuse: about 4,500 reuses suffice for full recovery, whereas a KEM with a re-encryption check would not leak this way. The NGCC evaluation explicitly takes security under temporary key reuse into consideration ([Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/tT7TSQiz.pdf) §1(3)); a submission cannot narrow that evaluation target through its own security-model disclaimer. The demonstrated full recovery is therefore High. The additional rollback/snapshot precondition keeps it below Critical.

Follow-up response: the [Loom team's 2026-09-29 post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/IYWTI3KKQX26OFA7AGT5OJ7L6D5UWUQ2/) says the decryption-failure rate is an intentional bandwidth trade-off and treats rollback and state restoration as outside its claimed model. The archived result and NGCC evaluation scope above are unchanged.

### Reproducing

```sh
make -C kex-05 exploit
kex-05/reproduce_state_rollback_key_recovery
```

Set `LOOM_ATTACK_SEED_TWEAK` to a nonnegative integer to generate an independent deterministic key pair for additional trials.

Expected output:

```text
ATTACK kex-05-2 LoomKEX-256 CONFIRMED rollback_queries=4532 accepts=1754 recovered_coefficients=1024 honest_passes=4 shared_secret_match=yes
recovered_ephemeral_sk_digest=cac8fae173f31fe3063ac092df0acf7e90f71a4bc20ae5b6e03168f110cd8d1b
shared_secret=2acee149b895cace5f7ebf94aa6ea9e2c504c7411b6e2e15edb4ad8e40b541f7
```

The reference run takes approximately 4.9 seconds on the development host.
The optimized implementation was independently cross-checked during analysis,
but its separate witness build is not included in the public harness and is not
needed to reproduce this finding.

## kex-05-3: Shuttle signing-key leakage enables permanent responder impersonation

Severity: Critical
Status: Confirmed
Layer: Design
Affected: LoomKEX-128, LoomKEX-256, and LoomKEX-512
Discovery: Non-trivial
Exploitation: 175,000/275,000/300,000 accepted handshakes for full identity-key recovery
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-29
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2OIYBCQOZQCKMO2DCKFMD2A4GE4RR5RM/)

Loom embeds Shuttle as its long-term authentication mechanism. At every level, the 13 source files implementing signing, sampling, and response encoding are byte-identical to the corresponding submitted Shuttle reference files. Figure 1, Eq. (8), and §4.1.1 define the transition as returning `y−v` on its selected interval, while Algorithm 22 and `irs.c:382–399` return `y+v` for that event. This reversed sign leaves secret-dependent covariance in accepted responses, and the signing secret's constant first component provides a public anchor for estimating the remaining coefficients. Loom's `loom.c` calls this signer for authentication and verifies the resulting signature in `loom_auth_ver`.

The reported formal-parameter experiment used 175,000, 275,000, and 300,000 accepted handshakes, recovered all 768, 1,536, and 3,072 identity-key coefficients exactly, and impersonated the responder in 20 of 20 fresh handshakes at each level. Restoring the transition sign makes the same estimator fail. We independently verified the byte-for-byte embedding and protocol call path. An independent public driver obtains ordinary signatures, estimates the challenge-conditioned covariance, checks the recovered coefficients through the public-key relation and key-generation bounds, and produces an accepted fresh-message signature using the resulting equivalent key.

Recovering the responder's long-term authentication key yields fresh-session impersonation and directly violates Loom's AKE authentication claim, hence Critical. A submitter response states that decryption-failure behavior and rollback security are out of scope; that position does not affect this independent identity-key recovery.

### Reproducing

```sh
python3 kex-05/validate_shuttle_embedding.py
make -C sign-23 exploit
tools/reproduce.sh sign-23
```

The first command checks the exact three-level source embedding and Loom authentication calls. The remaining commands run the public signature-only recovery and accepted-forgery witness against the byte-identical signing module; the original post reports the additional complete Loom handshake and impersonation trials.

## kex-05-4: Loom's ICCS build uses the external DRBG as an XOF

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: LoomKEX-128, -256 and -512 ICCS reference builds; the SHAKE build is not affected
Discovery: Trivial
Exploitation: Protocol expansion depends on the particular external RBG stream; the frozen ICCS build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

Loom's ICCS `xof256_init` resets an external `DRNG_ctx` from protocol input, and its squeeze function reads that stream (`loom/symmetric-iccs.c:90–103`). The wrapper is used throughout deterministic matrix, sampler and transcript expansion. A different secure RBG therefore changes the protocol values even though the interface is nominally a randomness source.

The submitted ICCS build works with its bundled `drng.c`, and Loom's SHAKE build supplies a defined XOF. This is a Low implementation/interoperability issue in the ICCS adaptation, not a key-exchange attack.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kex-05-4
```
