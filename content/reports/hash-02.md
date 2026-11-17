<!-- synchronized report: hash-02/report.md -->
Candidate: AXIS
Family: Symmetric (stream-cipher-style hash)
Archive: [AXIS.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/AXIS.zip) (SHA-256: `a7c6aa6d30642cc05207acb4d2aa3701dd40945cb21f1bc0e51305ca8f57f81d`)

## hash-02-1: Allocation failure returns a successful all-zero digest

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized AXIS-512/768/1024 bitstring-input paths
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

## hash-02-2: Partial-bit AXIS update branches on secret state, with a measurable timing dependence

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference and optimized AXIS-512/768/1024 on non-byte-aligned messages
Discovery: Moderate
Exploitation: Running time depends on the secret message at a fixed length, measured locally; no message or state recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

For non-byte-aligned input, `axis_core_hash_bits` leaves the bit-sliced byte-aligned fast path (`axis_core.c:1698-1704`). The scalar nonlinear update calls `axis_flip_bit` on state-derived bits (`:160,633-638,685-690`), and the digest is written bit by bit with a branch on each output bit (`axis_write_digest_bit`, `:1152-1158`). GCC `-O2` retains conditional jumps in these paths. This does not apply to the ordinary byte-aligned fast path.

The channel is measurable in the reference AXIS-512 built with the submission's own flags. For 501-bit messages the instruction count of a call varied between 2,332,745 and 2,334,747 over six random messages, and an all-zero message ran about 12,900 cycles faster than random ones (Welch t of 84 over 10,000 calls). A 504-bit control had a constant instruction count and no timing difference. The optimized tree showed the same branch and a larger difference. The figures vary with the host, and no message or state was recovered. See [constant_time.md](../constant-time/hash-02.md).

Constant-time fix (easy): apply each flip as a masked XOR, `reg[w] ^= (uint64_t)(-(bit & 1)) & mask`; the byte-aligned bitsliced path is already branch-free. The repair is local; the rating is Medium because the channel is measured.

### Reproducing

```sh
sh hash-02/reproduce_secret_branch_timing.sh
```

The witness requires the taint result and a message-dependent instruction count, with a byte-aligned control, and prints the timing figures as information. It needs Valgrind.

## hash-02-3: The invertible AXIS state caps AXIS-1024 second-preimage security at 768 bits

Severity: Critical
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

## hash-02-4: Digest alignment gives a below-target AXIS-1024 preimage route

Severity: Critical
Status: Probable
Layer: Design
Affected: AXIS-1024 specification and reference implementation
Discovery: Non-trivial
Exploitation: About 2^891–2^892 digest-state trials, each with polynomial overhead, plus a 2^768 meet-in-the-middle; no full preimage computed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-09

AXIS-1024 claims 1024-bit first-preimage security (Table 2, physical p. 12; §3.3, physical pp. 16–17). At the start of digest generation, each of the first 133 output bits has a fresh state bit that has not affected earlier outputs. Choosing those bits in sequence typically fixes 132–133 target digest bits; nonlinear gating can prevent one choice. The remaining 891–892 bits then cost about `2^891–2^892` trials under the usual random-remainder assumption. The first 66 positions follow directly from shifted register bits; the submitted digest extraction and update paths are in `axis_core.c:613–701,1150–1262`.

The 1024 blank beats can be inverted to obtain a required state after message absorption. With at least 1536 free message bits, a forward/backward meet-in-the-middle over 768 bits per side reaches that state in about `2^768` time and memory, as in the submitted invertible update. The `2^891–2^892` estimate counts digest-state trials, not bit operations; even a polynomial number of beats per trial remains below the 1024-bit target. The witness verifies 132–133 sequentially fixed bits across three trials and the inverse blank phase against a Python model cross-checked with the submitted C; it does not run either exponential search. The remaining-bit distribution and full-state reachability make the complete cost Probable, not a computed preimage.

### Reproducing

```sh
bash hash-02/reproduce_preimage_alignment.sh
```

The wrapper compiles the unmodified reference core into a temporary library, checks the independent model against 60 full hashes and 300 state steps, then verifies the digest-bit control and inversion. It leaves no build files behind.

## hash-02-5: Optimized message packing indexes tables with message bytes

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Optimized AXIS-512/768/1024 when built without BMI2, including the Makefile's portable and AVX2 targets
Discovery: Moderate
Exploitation: Cache side-channel dependent; no timing difference measured and no message recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

The optimized byte-aligned path packs each message block into two bit sequences. With BMI2 it uses `pext`. Otherwise it looks up every message byte in 256-entry tables: `axis_pack_even_lsb_table[block[i]]` and its companion table (`axis_core.c:1246-1274` in AXIS-512). `AXIS_HAS_BMI2` requires `AXIS_OPT_LEVEL` 3 and a compiler targeting BMI2 (`:24-28`), and the Makefile's portable and AVX2 targets pass `-mno-bmi2`, so both use the tables. Each table spans four cache lines, and the index is a secret message byte.

With the message marked as undefined under Valgrind's memcheck, a build without BMI2 reports the table reads in `axis_pack_message64_reverse_block` for a byte-aligned message. No running-time difference between an all-zero and random messages was found over 20,000 calls, so this remains a cache-line channel without a measurement.

Constant-time fix (easy, hence Low): compute the even- and odd-bit extraction with shifts and masks, as a portable replacement for `pext`.

### Reproducing

Build the optimized AXIS-512 with `-mno-bmi2` and inspect `axis_pack_message64_reverse_block`; the non-BMI2 branch reads `axis_pack_even_lsb_table` at an index taken from the message.
