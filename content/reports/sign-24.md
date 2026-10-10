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
