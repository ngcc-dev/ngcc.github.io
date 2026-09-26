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

## hash-02-3: The invertible AXIS state caps AXIS-1024 second-preimage security at 768 bits

Severity: High
Status: Confirmed
Layer: Design
Affected: AXIS-1024 specification and implementations; AXIS-768 is exactly at the bound
Discovery: Moderate
Exploitation: Approximately 2^768 beat evaluations and memory; no second preimage has been computed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-26

AXIS-1024 claims 1024-bit second-preimage security (Table 2, physical PDF page 12), which a generic meet-in-the-middle on its 1536-bit state violates.

Each beat reads only positions {0, 11, 12, 32, 96, 107, 125} of a 192-bit register, flips only positions {66, 75, 90, 162, 178, 188}, and rotates the register by one bit. The eight registers are updated in order (`def.h:20-34`, `axis_core.c:613-640`). For known message bits the beat is therefore a permutation of the full 1536-bit state, and it can be run backwards. AXIS-1024 supplies one independent message bit per beat, using that bit for both update inputs (`axis_core.c:813,1087,1133` in AXIS-1024). Given a target with a sufficiently long prefix, an attacker computes about 2^768 states forward from the IV over 768 free message bits and about 2^768 states backward from the target's intermediate state over another 768 free bits. Joining a match with the rest of the target keeps the length and the blank and digest beats unchanged. The resulting second preimage costs about 2^768 rather than 2^1024. The specification gives no second-preimage argument beyond setting it "conservatively" equal to the preimage level (page 17).

### Reproducing

The witness runs the submission's own `axis_step` forward for random states and message bits, then checks that an independent inverse restores each state for all three variants:

```sh
make -C hash-02 reproduce-inverse
```

It prints `ATTACK hash-02-3 CONFIRMED`.
