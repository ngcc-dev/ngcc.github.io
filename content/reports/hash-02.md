<!-- synchronized report: hash-02/report.md -->
Candidate: AXIS
Family: Symmetric (stream-cipher-style hash)
Archive: [AXIS.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/AXIS.zip) (SHA-256: `a7c6aa6d30642cc05207acb4d2aa3701dd40945cb21f1bc0e51305ca8f57f81d`)

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

## hash-02-2: Partial-bit AXIS update branches on secret state

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference AXIS-512/768/1024 on non-byte-aligned messages
Discovery: Moderate
Exploitation: Branch side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

For non-byte-aligned input, `axis_core_hash_bits` leaves the bit-sliced byte-aligned fast path (`axis_core.c:1698-1704`). The scalar nonlinear update calls `axis_flip_bit` on state-derived bits (`:160,633-638,685-690`); its generic and finalization paths retain conditional jumps under GCC `-O2`. Equal-length secret bitstrings can therefore change the branch trace. This does not apply to the ordinary byte-aligned fast path, and no timing extraction was demonstrated. See [constant_time.md](../constant-time/hash-02.md).

### Reproducing

Compile `AXIS-768/axis_core.c` with `gcc -O2 -g -c`; `objdump -dSl` shows conditional jumps at `axis_flip_bit` in `axis_step_generic`.
