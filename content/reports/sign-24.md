<!-- synchronized report: sign-24/report.md -->
Candidate: Sigurd
Family: Code-based (regular syndrome decoding)
Archive: [Sigurd.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Sigurd.zip) (SHA-256: `443ab14257658d89a60e14ad0d4b7f4df9fcdd06da4f42fcb29bbbfc75a97153`)

## sign-24-1: Chunked Reed–Solomon encoding reveals the signing witness

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Sigurd-128, -256, and -512 reference implementations
Discovery: Moderate
Exploitation: Witness recovery and accepted fresh-message forgeries from 4–8 ordinary signatures in independent tests
Credit: Guoxiao Liu (Tsinghua University); independently Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance; independently Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/2lO14yYyDK4/m/UYKYkWM7BAAJ)
Follow-up source: [Sigurd team's confirmation and repair](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5DEREMB3PTPDFONWGHOJ4MQR4OP3V3AQ/)

The specification's vector commitment pads the witness with fresh random tail elements and applies one Reed–Solomon encoding. The submitted `RS_encode` instead divides the input into 32 independently encoded chunks (`sig_core.c:640–745` in Sigurd-128; the same structure appears in the other reference sets). Early chunks contain only the unchanged witness prefix; the fresh tail cannot hide their evaluations. Signatures expose selected encoded-witness symbols, so openings accumulated across signatures interpolate those chunks. The public syndrome then determines the short remaining witness suffix. An independent whole-scheme witness recovered all 217/458/946 blocks from 4–8 ordinary signatures and forged a fresh message accepted by each submitted verifier; changing one recovered one-hot block made the control forgery reject. The flaw is in the submitted encoding, not the specified single-code construction.

The Sigurd team confirms that Guoxiao Liu first disclosed the issue privately and that Feussner and Saarinen found it independently shortly afterward. The frozen archive above remains the target of this finding.

### Proposed fixes

The [Sigurd team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5DEREMB3PTPDFONWGHOJ4MQR4OP3V3AQ/) proposes replacing the 32 short codes with one global Reed–Solomon code in every parameter set, regenerating the KATs, and making the evaluation domain explicit. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C sign-24 exploit
tools/reproduce.sh sign-24
```

The [independent driver](https://github.com/ngcc-dev/ngcc-harness/blob/dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/security/sigurd_chunk_recovery.c) queries `sig_sign` for ordinary signatures, parses only public transcripts, interpolates witness-only chunks, solves the remaining public-syndrome system, and calls the submitted `Prover` with the recovered witness. The original [forum analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/2lO14yYyDK4/m/UYKYkWM7BAAJ) reports broader 35-key testing; our witness tests two different keys at each level.

## sign-24-2: Zero 16-bit challenge exposes the signing witness

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Sigurd-128, -256, and -512
Discovery: Moderate
Exploitation: An unmodified Sigurd-128 signer naturally reached zero after 3,458 same-key signatures in one test stream, exposing the witness; the expected query count is about 2^16
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06
Follow-up source: [Sigurd team's 2026-10-10 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KZ6F7H6D7SFO6KUFF2E4UH3YKACH3AE4/)

The submitted implementation takes `zeta` from a 16-bit expansion word without excluding zero (`Sigurd-128/sig_core.c:1711–1728`, `Sigurd-256/sig_core.c:1717–1734`, and `Sigurd-512/sig_core.c:1717–1733`). The specification does not prescribe this scalar width or a `zeta`-scaled mask; its extension-field requirement is `ιτ > λ` precisely so the challenge and masking space is sufficiently large (physical p. 17). The code's final public response is `G = E + zeta * F` (`Sigurd-128/sig_core.c:1408–1452`). When `zeta=0`, masking term `F` disappears. The public response, public transcript, one-hot witness-block constraints, and public syndrome then form a linear system for the signing witness. Under the intended random-oracle interpretation of the XOF word, each signature has probability 2^-16 of this event. The signing and verification paths do not resample or reject zero. A recovered witness suffices for signing independently of the secret seed.

In a natural run, the unmodified Sigurd-128 signer reached `zeta=0` on the 3,458th signature of one same-key worker stream. Its submitted verifier accepted that signature, and a solver using only the public key, message, signature and derived transcript recovered the exact witness, checked against the secret kept separately. The run used parallel worker streams sharing that key; 3,458 is the count in the successful stream, not the aggregate across workers. No fresh-message forgery was executed. Independently, forced-zero test builds at all three levels yielded full-rank systems and exact witness recovery (ranks 1302/1302, 2748/2748 and 5676/5676). Same-seed nonzero controls were inconsistent and yielded no witness. The natural run confirms the trigger at 128; the higher levels are supported by source identity and forced-zero tests, not a natural long run.

### Proposed fixes

The [Sigurd team's 2026-10-10 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KZ6F7H6D7SFO6KUFF2E4UH3YKACH3AE4/) says its revised implementations take the first nonzero challenge word and make that rule explicit in the revised specification. It reports unchanged test vectors. The revision is recorded without evaluation.

### Reproducing

```sh
bash sign-24/reproduce_zero_zeta.sh
python3 sign-24/reproduce_natural_zero.py
```

Both wrappers build only in fresh temporary directories, with no changes to the submitted source tree. The first runs forced-zero and unforced controls at every level; the second uses up to 14 native workers to find a natural zero at 128. `solve_zero_zeta.py` receives only the public-equation file, and a separate file is used solely to check its recovered answer.

## sign-24-3: Signing rebuilds the public state with secret-dependent control flow

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Sigurd-128, -256, and -512, reference and optimized implementations
Discovery: Moderate
Exploitation: Source inspection and execution profiling establish repeatable control flow depending on the long-term witness; no timing or cache observation, witness recovery, or forgery is demonstrated
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-17
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DIUN6YFVFWQRI556USJFCCEELQ5FXGXR/)

Every signing operation calls `sig_build_public_state_direct`, which expands the secret `e_seed` into the long-term error vector `e` and evaluates the public matrix on it. Inside the public-matrix loop, all six submitted implementations branch on `e_bits[col]` before conditionally updating `y_bits` (`Reference_Implementation/Sigurd-128/sig_core.c:567,589–592`; corresponding reference lines 573,595–598 at 256/512; optimized lines 2271–2274, 2120–2123 and 2324–2327). The branch condition is therefore secret and repeats under every signature made with one key. Replacing the conditional update with a masked or unconditional XOR is a local implementation change.

The forum post reports callgrind profiles in which the body count changes when only the secret portion of a hybrid key changes and remains stable across messages and signing randomness for one key. Its statement that this count equals the Hamming weight of `e` is not literal: `random_e` sets exactly one position in each six-coordinate block, so the weight is fixed. Because the secret branch is nested under the public matrix-bit branch, the count is instead a public-matrix-weighted function of the secret support. This correction does not remove the secret-dependent control flow. No externally observable timing or cache channel, and no route from the aggregate counts to key recovery, was demonstrated; the finding is Low under the side-channel policy.

### Reproducing

```sh
python3 sign-24/reproduce_secret_branch.py
```

The certificate checks all three reference and all three optimized sources for the fixed-weight secret expansion, the signing-time state reconstruction, and the conditional update on `e_bits`. It does not replay the reporter's callgrind measurements.
