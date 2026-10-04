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

## sign-30-2: The specified 128-bit round seeds permit collision-accumulation forgeries

Severity: Critical
Status: Confirmed
Layer: Design
Affected: TRINE-128 Balanced and TRINE-128 ShortSig specification; submitted C implementation is salted and excluded
Discovery: Hard
Exploitation: At most 2^64−1 ordinary signatures and about 2^94.25 or 2^96.99 attacker cycles, below the 128-bit target; full-size execution was not run
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-10-04
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/2VDYFLE2UZG5ASUDLWANL5OTSRWTOTQ7/)

The [pinned analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/6ebb3b4ab00c68d8e72b1c08ba839ed7056dc166/TRINE) validates the following result.

The direct specification uses unsalted 128-bit per-round seeds (Algorithms 6–8, physical pp. 13–14; parameter tables, p. 15). Birthday collisions at a fixed round therefore make two ordinary signatures share the same decoded round object. Their different opened labels expose equivalences that can be accumulated: one edge suffices for Balanced, while ShortSig uses a connected label graph. The recovered equivalences yield a valid witness and a fresh-message forgery.

At `2^64−1` signing queries, exact ideal-model tables give roughly 50% success with total attacker costs of `2^94.25` cycles for Balanced and `2^96.99` for ShortSig, below the 128-bit claim. The artifact validates the resource model, executes reduced-seed forgeries through the specification-aligned verifier, and confirms at full entropy that the specified signature layout works. The submitted source adds a 256-bit signature salt and is not affected, but its signatures are 32 bytes longer than the specified format.

### Reproducing

```sh
sh sign-30/reproduce_seed_collision.sh
```
