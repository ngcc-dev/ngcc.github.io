<!-- synchronized report: kem-12/report.md -->
Candidate: CTL
Family: Lattice-based
Archive: [CTL.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CTL.zip) (SHA-256: `512caaf5fa04ea5ab51fb5eeee9e81f8c7c7c430b60727130067634bfb674d01`)

## kem-12-1: The specified CTL-512 public-key space has at most 256 bits of support

Severity: Critical
Status: Confirmed
Layer: Design
Affected: CTL-512 specification and reference implementation
Discovery: Trivial
Exploitation: Approximately 2^256 key-generation trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [CTL submitters' 2026-09-23 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/)

CTL-512 claims 512-bit security, but its normative short private-key format stores one 32-byte key-generation seed. The specification requires `f` and `g` to be regenerated deterministically from this seed and recomputes the public key as `h = f^-1 g mod q`.

Consequently, at most `2^256` public keys can be generated. An attacker can enumerate the seeds, recompute `h`, and compare it with the target public key; a match recovers the target trapdoor data. This ceiling is independent of the nominal lattice dimensions and is present in both the specification and submitted code.

### Proposed fixes

The [CTL submitters' response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/) proposes a 64-byte CTL-512 key-generation seed, an expansion mechanism intended to preserve the target level, corresponding private-key and deterministic-regeneration changes, and a review of the complete entropy path. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-12-1
```

The `kem-12-1` check verifies the short-key algorithms on physical PDF pages
24 and 28–36 and the corresponding reference constants.

## kem-12-2: CTL-512 returns only 384 shared-secret bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: CTL-512 reference adapter; the specification assigns a 64-byte output
Discovery: Trivial
Exploitation: The 384-bit output is 128 bits short of the required 512-bit encapsulated key
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [CTL submitters' 2026-09-23 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/)

The CTL-512 adapter returns a 48-byte shared secret and instantiates the ciphertext hash component `c2` at 48 bytes. The specification assigns 64 bytes to CTL-512 `c2`.

The returned key therefore has at most 384 bits of delivered-key capacity and the ciphertext format contradicts the PDF. The NGCC [Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf) §2(2) require the encapsulated key to be at least as long as the corresponding classical security level. CTL-512 misses that explicit 512-bit target and is therefore Critical, even though this dimensional shortfall is not a separate IND-CCA attack. The CTL submitters acknowledge both findings; these reports remain scoped to the archived submission.

### Proposed fixes

For CTL-512's shared secret and `c2`, the [submitters' response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/H47RU2HKEEAZQOJNKMUFWNEJEHHSLPQQ/) proposes revising the length handling, key derivation, implementation, specification, documentation, test vectors, and validation. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-12-2
```

The `kem-12-2` check verifies the CTL-512 output table and the corresponding
reference constants.
