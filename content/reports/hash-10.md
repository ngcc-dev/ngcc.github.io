<!-- synchronized report: hash-10/report.md -->
Candidate: FEILIAN
Family: Symmetric (matrix-based hash)
Archive: [FEILIAN.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/FEILIAN.zip) (SHA-256: `876082a40ecf3b25d8b19478cbfeab4bd5f96ff7a293aacc5b57a9f73c2ff26c`)

## hash-10-1: Padding-allocation failure returns a successful all-zero digest

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference FEILIAN512/768/1024
Discovery: Moderate
Exploitation: Resource-contingent false-success digest; not a normal-operation cryptanalytic collision
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

FEILIAN's `pad_message` returns zero when its padded-message allocation fails. The hash core then zeroes the requested digest, while the public `CryptHash` API returns success. Under a bounded address space, two distinct 16-MiB byte-aligned messages both returned `0` and the same all-zero 512-bit digest. A changed-message control yields distinct digests with available memory, and the ordinary FEILIAN512 KAT passes.

This is a resource-contingent implementation failure, not a collision in the successfully executed FEILIAN construction. It is relevant when a caller accepts a digest after the library silently fails; allocation failure should be returned as an error.

### Reproducing

```sh
make -C hash-10 exploit
```

The Linux witness preallocates the input, caps process virtual memory at its current use plus 4 MiB, and verifies both successful zero-digest responses.
