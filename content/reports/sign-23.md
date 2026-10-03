<!-- synchronized report: sign-23/report.md -->
Candidate: Shuttle
Family: Lattice (Module-LWE/Module-SIS)
Archive: [shuttle.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/shuttle.zip) (SHA-256: `09253fd33c2215098177991db3375cb94e4e4a73a65b019783edabefa5bd8a62`)

## sign-23-1: Reversed transition leaks Shuttle's signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Shuttle-128, -256, and -512 NGCC specification and reference implementations
Discovery: Non-trivial
Exploitation: Equivalent-key recovery and accepted fresh-message forgeries from 175,000/275,000/300,000 valid signatures in independent 128/256/512 tests
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/5ao-Ebsa_Ow/m/zwYJk_Q-BAAJ)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §7](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

Figure 1, Eq. (8), and §4.1.1 define `p_v(y)` as the probability of returning `y−v`, but Algorithm 22 sets its flag on the corresponding interval event and returns `y+flag·v`. All three reference `irs.c` files implement that same sign (`irs.c:382–399`). Reversing the intended transition leaves a secret-dependent covariance in valid responses. The constant first component of Shuttle's signing secret supplies a public anchor for estimating the other secret components. An independent driver recovered an equivalent key using only ordinary signatures and the public key, then produced an accepted fresh-message forgery at every level. The original analysis also reports a corrected-sign control; that control has not been independently rerun. The authors' separate [ePrint 2026/1991](https://eprint.iacr.org/2026/1991) uses the matching `y−v` branch, so this finding concerns the NGCC submission.

### Reproducing

```sh
make -C sign-23 exploit
tools/reproduce.sh sign-23
```

The [independent driver](https://github.com/ngcc-dev/ngcc-harness/blob/dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/security/shuttle_covariance_recovery.c) parses verified signatures, accumulates challenge-conditioned covariance, checks recovered secret coefficients through the public-key relation and key-generation bounds, and signs a fresh message with the resulting equivalent key. It splits ordinary signing queries over eight independent processes by default; no original secret data enters the estimator or public completion. The [original post](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/5ao-Ebsa_Ow/m/zwYJk_Q-BAAJ) describes the same mechanism.

## sign-23-2: Shuttle's ICCS build uses the external DRBG as an XOF

Severity: Low
Status: Confirmed
Layer: Design
Affected: SHUTTLE-128, -256 and -512 ICCS reference builds; the SHAKE build is not affected
Discovery: Trivial
Exploitation: Signer and verifier depend on the particular external RBG stream; the frozen ICCS build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

In the ICCS path, `xof256_init` resets an external `DRNG_ctx` from protocol input and `xof256_squeeze` reads its output (`symmetric.c:73–86`). Shuttle uses this wrapper for public expansion, commitments, challenges and signing/verification transcripts (`sign.c:319,423,702,714`; `polyvec.c:109–135`). The exact ICCS DRBG stream is consequently part of signature interoperability.

The specification makes this choice itself: under the default NGCC mode its unified XOF "collapses onto a single SM3 Hash-DRBG" supplied by the API, and the squeeze schedule is pinned to that DRBG's generate calls (physical p. 109). The reliance on the external RBG's determinism is therefore in the design, not only in the code. The alternate SHAKE path supplies a defined XOF and is outside this finding. The ICCS mode should likewise use a scheme-defined XOF rather than reset an external RBG.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id sign-23-2
```
