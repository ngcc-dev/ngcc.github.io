<!-- synchronized report: hash-02/report.md -->
Candidate: AXIS
Family: Symmetric (stream-cipher-style hash)
Archive: [AXIS.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/AXIS.zip)

## hash-02-1: Allocation failure returns a successful all-zero digest

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference AXIS-512/768/1024 bitstring-input paths
Discovery: Moderate
Exploitation: Resource-contingent false-success digest; not a normal-operation cryptanalytic collision
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

For non-byte-aligned input, AXIS reserves memory to store the message bits. If that allocation fails, `axis_core_update_bits` records the failure, `axis_core_final` writes an all-zero digest, and the public `CryptHash` API still returns success. Under a bounded address space, two distinct 16-MiB-minus-one-bit inputs both returned `0` and the same all-zero 512-bit digest. A changed-message control produces distinct digests when memory is available; the ordinary AXIS-512 KAT passes.

This is a resource-contingent implementation failure, not a collision in the successfully executed AXIS construction. A caller that trusts the success return can accept a predictable digest for arbitrary input. Allocation failure must propagate as a nonzero API result, and callers must not use the output on error.

### Reproducing

```sh
make -C hash-02 exploit
```

The Linux witness preallocates the input, caps process virtual memory at its current use plus 4 MiB, checks two distinct messages, and enforces a short timeout if allocation unexpectedly succeeds.
