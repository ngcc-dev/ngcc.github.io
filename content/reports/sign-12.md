<!-- synchronized report: sign-12/report.md -->
Candidate: Galas
Family: Symmetric (MPC/VOLE-in-the-Head)
Archive: [Galas Signature.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Galas%20Signature.zip) (SHA-256: `98d57af868fa10d74b2c0656e565aa14a42ff902646d6fc440ffb7355b75342c`)

## sign-12-1: Publicly reproducible signing keys

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all submitted parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The signing wrapper constructs a private DRNG but does not seed it from the API-provided `drng_algorithm`. Unless a non-API test helper is called, it initializes that generator with 32 zero bytes.

Independent fresh-process tests against Galas-160F generated identical public and secret keys in separate processes. The same implementation pattern is shared by the submitted Galas instances.

An attacker recovers the signing key by running the public key-generation implementation from its initial state. The advertised hard relation is irrelevant because the victim and attacker deterministically generate the same secret key.

Key generation must obtain its seed exclusively from the initialized API DRNG and must not provide a zero-seed production default.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-12
tools/ngcc_attack keygen-determinism sign-12/lib/libGalas-160S.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## sign-12-2: 32-bit message-length truncation enables long-message forgeries

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All eight reference variants on platforms with 32-bit unsigned; runtime confirmation on Galas-160F and Galas-256F
Discovery: Trivial
Exploitation: One signing query and a 64-bit process able to reserve a 4 GiB virtual mapping
Credit: pq-CUC
Date: 2026-09-30
Original source: [pq-CUC's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/7GPLR732HEXNMYOT37KSQDVDVHIRR2GH/)

Galas claims EUF-CMA security (§1.1 and §9.1). The reference API accepts a
64-bit byte count, but both signing and verification cast `m_len_bytes` to
32-bit `unsigned` before hashing (`ngcc/SIG_AlgorithmInstance.c:291,413`).
The helper itself takes an `unsigned msg_len` and passes only that many bytes
to H2 (`galas/sign_helpers.c:8-15`). These files are byte-identical across all
eight reference variants.

Consequently, a signature requested on any short message `M` also verifies on
the distinct message `M || X`, where `|X| = 2^32` bytes: both lengths reduce
to `|M|` inside the message hash. This is a one-query fresh-message forgery,
not only a large-input correctness failure. It is also within the call's
required message range of up to `2^63` bits
([Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf)
§2(2)).
The submitted optimized implementation was not assessed.

### Proposed fixes

The original post proposes hashing the entire message with its full 64-bit
length, or explicitly rejecting lengths the implementation cannot process,
and adding tests across the `2^32`-byte boundary. This section records the
proposal without evaluating it.

### Reproducing

```sh
make -C sign-12 reproduce-long-message
```

The witness signs 38 bytes and reserves, without physically allocating, a
`2^32 + 38`-byte anonymous mapping with the same prefix. Galas-160F and
Galas-256F accept the original signature for the long message and continue to
accept after its last byte changes; changing the first byte is rejected. The
two runs use about 6 MiB and 13 MiB peak resident memory, respectively.
