<!-- synchronized report: kem-38/report.md -->
Candidate: UVW Key Encapsulation Mechanism
Family: Code-based
Archive: [UVW-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/UVW-KEM.zip) (SHA-256: `f9a1b135ea16aca0c974861732e03cd3164f1288f33ff150ff66c98326b75bcb`)

## kem-38-1: UVW-512 derives its encryption pair from only 256 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: UVW-KEM-512 reference and optimized implementations
Discovery: Trivial
Exploitation: Approximately 2^256 H1-seed trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

UVW-512 claims 512-bit classical security. The specification models `H1(m)` as a hash directly into the full encryption pair `(r,e)`, but the implementation first hashes `m` to a fixed 32-byte seed and then deterministically expands that seed into `(r,e)`.

An attacker can enumerate the at most `2^256` H1 seeds, expand each candidate `(r,e)`, and test the public equation `c1 = rG + e` against the challenge. A match recovers `m = c2 XOR H3(r,e)` and therefore the session key. This caps the implemented UVW-512 confidentiality at 256 classical bits and 128 quantum bits under generic search, independently of its nominal code-decoding parameters. The 256-bit intermediate is not specified by the PDF, so this is an implementation rather than specification-level break.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-38-1
```

The `kem-38-1` check verifies the 512-bit claim and `H1` type in the PDF and the 32-byte H1 seed in the submitted source.

## kem-38-2: UVW exposes a stable list-decoding failure oracle

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: UVW-KEM reference implementation, all parameter sets
Discovery: Trivial
Exploitation: Decryption-failure oracle; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The decapsulator returns `-2` when randomized PKE list decoding fails, but `-1` when decoding succeeds and a later hash or re-encryption check fails. These paths are also dramatically separated in time because the failing decoder exhausts its retry bound.

For one deterministic UVW-128 key and valid ciphertext, flipping ciphertext bit 0 returned `-2` after about 49.3 seconds; flipping bit 846 returned `-1` after about 0.81 seconds on the same host. Thus an attacker can distinguish a secret-dependent decoder failure through both API status and a roughly 60-fold timing gap. This supplies the oracle primitive used by reaction attacks, but this audit has not yet converted it into full secret-key recovery.

### Reproducing

```sh
make -C kem-38 lib/libUVW-KEM-128.so
python3 security/kem_mutation_oracle.py \
  kem-38/lib/libUVW-KEM-128.so --bits 0,846
```

The seeds, mutations, return codes, and timings are deterministic. The slow `-2` witness takes about 50 seconds on the audit host.

## kem-38-3: Retry reactions may expose UVW-KEM-128 session keys

Severity: High
Status: Lead
Layer: Side-channel
Affected: UVW-KEM-128 reference implementation; higher sets not tested
Discovery: Non-trivial
Exploitation: Conditional recovery from about 1.06 million precise first-attempt reaction labels; an uninstrumented timing classifier is not demonstrated
Credit: Tianyuan Xie (on behalf of the openHiTLS team; with AI assistance)
Date: 2026-09-24
Original source: [NGCC PKC Forum post and attached reproducer](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/A6PUI23BHC7YNE5UQ3SMRO33GDBWCF2P/)

UVW's secret monomial transform hides 430 column pairs and their ratios. A chosen valid ciphertext whose error has a nonzero equal-scaled value in a hidden pair can make the first information-set decoding attempt retry. Conditioning public error samples on that reaction enriches the true pair/ratio triples. With the pairs recovered, a public `Δ` projection cancels the duplicated component, exposes a generalized Reed–Solomon image, and permits decoding a fresh ciphertext and deriving its exact 512-bit session key. This is a candidate-specific exploitation path for the retry behavior, distinct from `kem-38-2`'s final-status oracle on malformed ciphertexts.

The attached package's reference source matches the archived UVW-KEM-128 source (apart from an omitted build file). It validates an **instrumented** retry counter on real `kem_dec`, then recovers all 430 pairs and the target secret (`E2E_OK`). Its high-volume phase, however, reads the secret key to simulate 1,055,028 first-attempt reactions; it does **not** send those ciphertexts to the real decapsulator. A reported local timing check on 100 real valid decapsulations found 99 one-attempt calls averaging 811 ms and one three-attempt call at 896 ms; no runnable timing check is supplied. In the package's 60 real-decapsulation channel checks, only two ciphertexts were bad (one did not retry), too few to validate a reaction classifier. Thus the full public-interface attack remains a lead conditional on an observable, sufficiently accurate retry signal; the package does not demonstrate black-box shared-secret recovery. The structural attack does not depend on the contest hash/XOF placeholders being weak.

### Reproducing

Download the [forum attachment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/A6PUI23BHC7YNE5UQ3SMRO33GDBWCF2P/attachment/4/uvw-kem-128-reaction-poc.tar.gz) (SHA-256 `9ae70267f8244247270f5d5e6e8edc34f87ba180cb0b340b2c6926f24b3e9fd9`), inspect its `README.md` and `attack/run_attack.sh`, then run it with a Python environment providing NumPy:

```sh
T=$(mktemp -d)
curl -fL -o "$T/poc.tar.gz" \
  'https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/A6PUI23BHC7YNE5UQ3SMRO33GDBWCF2P/attachment/4/uvw-kem-128-reaction-poc.tar.gz'
printf '%s  %s\n' '9ae70267f8244247270f5d5e6e8edc34f87ba180cb0b340b2c6926f24b3e9fd9' "$T/poc.tar.gz" | sha256sum -c -
tar -xzf "$T/poc.tar.gz" -C "$T"
cd "$T/uvw-kem-128-reaction-poc/attack"
python3 -c 'import numpy'  # activate an environment with NumPy if needed
bash run_attack.sh
```

The package compiles the submitted code, checks its two-line counter instrumentation, tests the real decoder channel, simulates the high-volume labels, and finishes with a fresh ciphertext and `E2E_OK`. The distinction between real decapsulation and secret-assisted simulation is essential when interpreting the result.
