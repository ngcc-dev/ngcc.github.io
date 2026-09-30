<!-- synchronized report: sign-30/report.md -->
Candidate: TRINE
Family: Trilinear-form group-action signature
Archive: [TRINE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/TRINE.zip) (SHA-256: `4b22f54b07509833b08d32402ffe06d7566e4c87622f9931079e791c80f4765d`)

## sign-30-1: The normal build deterministically exposes every signing key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Normal SHA3 reference build, all six parameter sets; ICCS/KAT build excluded
Discovery: Trivial
Exploitation: One local key generation reproduces the victim's signing key and enables forgery
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-30
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QENJSR2GEVLS5BF54E2JGKCOGDNL5ANN/)

The submitted normal build compiles every parameter set with `-DUSE_SHA3` and links `randombytes.c` (`Makefile:33–46,53–67`). Its global AES-CTR DRBG state is zero-initialized, `randombytes.h` exposes no initialization function, and no normal-build caller invokes `randombytes_init`. Key generation immediately obtains the complete secret seed from this state (`trine.c:178–213`). The separate ICCS/KAT path uses `randombytes_iccs.c` and is not affected.

Every fresh normal-build process therefore generates the same public and secret key. An attacker can locally repeat key generation and sign an arbitrary fresh message under the victim's public key. The source pattern is identical across the six normal reference builds, so this is a complete EUF-CMA break rather than only reduced key entropy.

### Reproducing

```sh
python3 sign-30/reproduce_unseeded_forgery.py
```

The witness compiles the archived TRINE-128-ShortSig normal sources. Independent victim and attacker processes produce identical complete key pairs; the attacker secret signs a fresh message accepted under the victim public key. Explicitly distinct DRBG seeds give distinct keys as a control.
