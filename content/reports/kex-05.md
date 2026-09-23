<!-- synchronized report: kex-05/report.md -->
Candidate: Loom
Family: Hybrid lattice KEM/signature AKE
Archive: [Loom.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Loom.zip) (SHA-256: `e9e7ff0fb453a371634797febeaeac7c1f081b5fd2438204787c763667482ec4`)

## kex-05-1: The specified decryption-failure rate causes honest-session aborts

Severity: Medium
Status: Confirmed
Layer: Design
Affected: LoomKEX-256 construction and submitted reference implementation
Discovery: Non-trivial
Exploitation: Observable honest-session failure; this witness alone does not recover a key (see the separate state-rollback finding `kex-05-2`)
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The Loom specification reports a decryption-failure rate of `2^-18.9` for LoomKEX-256. Its four-pass AKE treats rigid KEM decapsulation failure as a protocol abort rather than recovering or retrying internally, so the stated rate predicts failures in complete honest exchanges.

A deterministic whole-scheme search found such an exchange at global trial index `136129`. Both parties generate honest long-term keys, pass 1 produces 1,352 bytes, and pass 2 produces 1,384 bytes. The initiator's `kex_generate_pass3_msg_a` then returns `-3` because it cannot decapsulate the responder's honestly generated KEM ciphertext. Messages 3 and 4 remain absent and neither party produces a shared secret.

The submitted scalar reference implementation reproduces the recorded seed, keys, states, pass-1/pass-2 messages, failure stage, and return code exactly. The separately submitted optimized implementation produces the same transcript and failure, but it is not required to reproduce this finding.

This is a confirmed specification-level correctness and reliability defect with an observable failure surface. This honest-failure witness alone does not establish confidentiality loss, authentication failure, or key recovery. The separate `kex-05-2` finding demonstrates key recovery when the serialized pass-1 state can be rolled back.

The complete witness is `security/loom256_failure_witness.txt`; its SHA-256 digest is `b957dac32f2b3dfd0e689c0ea47bf7281cdc1bebbf48303e491be052a9067168`.

### Reproducing

Build the submitted scalar reference implementation and replay only the known witness index:

```sh
make -C kex-05 replay
kex-05/reproduce_failure 136129 1 1 /tmp/loom-witness.txt 0
sha256sum /tmp/loom-witness.txt
```

The replay reports `stage=pass3 code=-3`. The generated reference witness differs from the retained optimized witness only in its `implementation=` metadata line; all cryptographic and protocol fields are byte-identical. The longer deterministic search procedure and cross-check are documented in `security/LOOM_FAILURE_SEARCH.md`.

## kex-05-2: Resettable pass-1 state enables ephemeral-key recovery

Severity: High
Status: Confirmed
Layer: Implementation
Affected: LoomKEX-256 reference and optimized implementations when a pass-1 state can be snapshotted, rolled back, or evaluated concurrently
Discovery: Non-trivial
Exploitation: 4,532 chosen pass-2 queries in the deterministic witness
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Loom's security argument says an attacker observes at most one failure bit for each ephemeral KEM key. The submitted API does not cryptographically enforce that condition: the complete ephemeral KEM secret is held in a caller-managed serialized state, and `kex_generate_pass3_msg_a` reconstructs its working context from that byte string on every call. A caller or deployment that snapshots the pass-1 byte string can therefore evaluate arbitrarily many chosen pass-2 messages under the same ephemeral secret.

The exploit creates tagged Loom-KEM ciphertexts whose message is known and whose `u` component contains one sparse coefficient. It places one `v` coefficient exactly at the message-decoder boundary. Pass 3 emits a message precisely when the corresponding signed secret coefficient lies on the selected side of that boundary. Two probes identify whether each coefficient is positive, negative, or zero; three further threshold probes recover the magnitude of every nonzero CBD-8 coefficient in `{1,...,8}`. The remaining output coefficients are placed safely within the expected decoding region, so each answer isolates the intended coefficient.

The deterministic run recovers all 1,024 coefficients of the four-polynomial ephemeral secret after 4,532 complete `kex_generate_pass3_msg_a` calls. The recovered key successfully decapsulates an independently generated honest pass-2 ciphertext. The exploit then completes honest passes 3 and 4 and derives both parties' shared secrets; independently applying Loom's KDF to the attacker-recovered KEM key produces the identical 32-byte AKE shared secret. The submitted scalar and AVX2 implementations reproduce the same recovered-key digest, query counts, transcript result, and shared secret.

As a control against a seed-specific construction, the reference exploit was also run with `LOOM_ATTACK_SEED_TWEAK=0` through `7`. All eight independently generated ephemeral keys were recovered and all eight completed-session secrets matched; the query counts ranged from 4,481 to 4,592 according to the number of zero CBD coefficients.

This is a concrete key-recovery attack under state rollback, snapshot restoration, or sufficiently concurrent evaluation of the same serialized pass-1 state. It does **not** establish that a strictly linear deployment which irreversibly commits the state after the first accepted pass-2 message is remotely exploitable: an accepted probe advances the live state, so the proof of concept restores its saved snapshot before every query. Deployments must therefore make the state non-clonable and anti-rollback, atomically consume it before decapsulation, and erase it on every success or failure. Merely wiping the temporary unpacked context is insufficient.

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
