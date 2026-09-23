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
