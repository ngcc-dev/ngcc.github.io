<!-- synchronized report: sign-08/report.md -->
Candidate: DARTS
Family: Lattice-based
Archive: [DARTS.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DARTS.zip) (SHA-256: `1846cfe63f0cef83e2e0ca21f5dcadce3c4b16da33713957be6d156e2a9e6e95`)

## sign-08-1: The implemented message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: DARTS-512 reference implementation and specification
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

DARTS-512 claims 512-bit classical security and binds messages through the unsalted representative `mu = H1(pk, M)`. The submitted implementation emits only 64 bytes. A generic collision therefore costs about `2^256` evaluations and transfers a requested signature from one colliding message to the other.

The PDF names `H1` but does not define its output length. The concrete implementation ceiling is confirmed, while the missing length prevents classifying 64 bytes as a clean normative design parameter. This is an implementation security ceiling and a specification omission.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The check verifies the DARTS-512 algorithm on physical PDF pages 4, 8, and 12–13 and traces its 64-byte `mu`.

## sign-08-2: The compression-consistency restart leaks an equivalent DARTS-128 signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: DARTS-128 as specified and implemented; the other parameter sets were not tested
Discovery: Non-trivial
Exploitation: About 20–30 million public signatures, followed by seconds of CPU work
Credit: Bing Shi <roadicing@gmail.com>
Date: 2026-09-26
Original source: [Shi's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/62AUZI56IWGEN34OQTD6Z2U6APFMRYWC/) and [public proof of concept](https://github.com/roadicing/darts-key-recovery-attack/tree/5df01ac2b3e4b7a804fae5b3c5b4f8ad531cdaff)

Step 9 of Algorithm 7 accepts every signing attempt when the hidden branch bit is `b=1`, but for `b=0` accepts only when `Comp_d(omega) = Comp_d(omega+c alpha)`. Because `omega=A round(y)`, this asymmetric restart tilts the joint distribution of the published challenge and rounded response by a small key-dependent multiple of the sparse secret. Shi separates that impulse train from a smooth fixed bias, then enumerates the few uncertain coefficients and checks candidates with the exact public relation `e=(q+1)/2 beta-A s mod q`, requiring ternary `e`.

We replayed the pinned PoC's accumulators from 20,000,000 DARTS-128 signatures. The collector derives them only from decoded public signature fields. The full data estimated 19,983,582 samples, measured a `656.87`-sigma signal, and recovered all secret polynomials after 40,342 public-relation candidates. The recovered bytes before the independent signing seed matched the submitted secret-key control exactly. Setting that irrelevant seed to zero still produced a fresh-message signature accepted by the untouched submitted verifier; changing one message byte was rejected. This is therefore equivalent signing-key recovery and an EUF-CMA forgery, not merely a distinguisher.

### Reproducing

```sh
make -C sign-08 exploit-key-recovery
```

The wrapper clones and verifies the pinned attack commit, builds its public-relation checker against this repository's archived DARTS-128 source, replays the published accumulators, and tests a fresh signature with the recovered key. It requires Git, a C compiler, and a Python interpreter with NumPy; set `NGCC_SAGE_PYTHON` when NumPy is available only in a Sage environment. The original 20-million-signature collection is not repeated.
