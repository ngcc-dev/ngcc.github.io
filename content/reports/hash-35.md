<!-- synchronized report: hash-35/report.md -->
Candidate: Wish
Family: Symmetric (AES-derived sponge hash)
Archive: [Wish.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Wish.zip) (SHA-256: `f878ea89f5b5929c26445a4b1967f21139c74600d5779e4eb5d0bd7f97bea4b5`)

## hash-35-1: Secret-indexed S-box and variable-time field multiplication

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference Wish512 and Wish1024
Discovery: Trivial
Exploitation: Cache or branch side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Every permutation round reads `S_Box[s[i]]` with an evolving secret state byte (`wish.c:98`). Its 256-byte table spans cache lines. `GF_Mul` also loops until a secret-dependent multiplier becomes zero and branches on each multiplier bit (`:86-91`). This gives both memory-address and control-flow leakage; no full preimage recovery is claimed. See [constant_time.md](../constant-time/hash-35.md).

Constant-time fix (easy, hence Low): use `aesenc`/`vaeseq` as the specification intends, with a `pshufb` or bitsliced AES fallback; `GF_Mul` becomes a fixed eight-step shift and masked-XOR multiplication.

### Reproducing

Inspect `wish.c:86-99` in either reference variant. With multiplier `b=1`, `GF_Mul` executes one iteration; with `b=128`, it executes eight.

## hash-35-2: Unsupported digest lengths corrupt heap memory in the reference implementation

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference Wish512 and Wish1024
Discovery: Trivial
Exploitation: A request for an unsupported digest length writes past a heap allocation, or reads and writes far outside it; the bytes written are zeros, counters and constants, not message data; no control-flow hijack demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; independently reported by LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-17
Follow-up source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/3ML3M6J66GFEZSKRHVY2S4C2J3X23S7K/), posted after this entry was published

The reference `CryptHash` passes `digest_len_bits` and twice that value to `Wish_hash` without any check (`CryptHash_AlgorithmInstance.c:18-24`). `Wish_hash` allocates a state of ⌊2d/128⌋ 16-byte lanes and then clears ⌊2d/8⌋ bytes (`wish.c:168-169`). Whenever d is not a multiple of 64 the `memset` runs past the allocation: 66 bytes into a 64-byte block for 264 bits, 125 into 112 for 500, 250 into 240 for 1000.

Other lengths fail differently. Below 64 bits the lane count is zero, so the round constants and block counter are XORed into a zero-byte allocation and one bit is written at `state[num_lanes-1]`, far outside it; an 8-bit request aborts or faults. Lengths below 1024 other than 512 also read the mixing table past the state, so a 256-bit request returns 32 bytes that differ from call to call. A 2048-bit request reads past the table and faults, a zero request divides by zero, and a negative one starts a memset of hundreds of megabytes.

Under AddressSanitizer both reference builds report the heap overflow for 264-, 500- and 1000-bit requests. The supported lengths are unaffected.

Fix: reject every length other than the instance's own before allocating.

### Reproducing

```sh
sh hash-35/reproduce_digest_length.sh
```

The witness needs AddressSanitizer for this part. It also checks `hash-35-3`.

## hash-35-3: Optimized wrappers ignore the requested digest length

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Wish512 and Wish1024, x86 performance- and resource-optimized implementations; the ARM wrappers are identical by source
Discovery: Trivial
Exploitation: A caller that sizes the output buffer from a shorter requested length receives a write beyond it; no secret disclosure or cryptographic break shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; independently reported by LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-17
Follow-up source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/3ML3M6J66GFEZSKRHVY2S4C2J3X23S7K/), posted after this entry was published

The optimized wrappers discard the parameter with `(void)digest_len_bits;` (`CryptHash_AlgorithmInstance.c:17`), return 0 and always write the full 64- or 128-byte digest. All four x86 builds do this for 8- and 256-bit requests.

Fix: return an error unless `digest_len_bits` equals the instance's digest length.

### Reproducing

```sh
sh hash-35/reproduce_digest_length.sh
```

## hash-35-4: Aligned SSE loads crash the x86 implementations on unaligned buffers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Wish512 and Wish1024 x86 resource- and performance-optimized implementations built with their Makefile flags; the reference, AVX builds and ARM implementations are not affected
Discovery: Trivial
Exploitation: Valid calls crash: the resource-optimized builds on short messages and on unaligned ones, the performance-optimized builds on messages not aligned to 16 bytes; no memory corruption
Credit: LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-19
Original source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/3JLPLVQZRQWTWUOYIEKX73LE5OVHXMGE/)

All four x86 `wish.c` files define `LOAD(p)` as `_mm_load_si128` (`wish.c:17`), which requires 16-byte alignment, and apply it to the caller's message blocks and to the stack array `padded_block`, which has no alignment attribute (Wish512 `:157–167`, Wish1024 `:181–191`). Built by GCC 15 with the Makefile flags (`-march=x86-64 -maes`, legacy SSE), the resource-optimized builds crashed on an aligned 24-bit message, because `padded_block` was placed at 8 mod 16, and the performance-optimized builds crashed on one- and two-block messages at offsets 1 and 8 while matching the reference on aligned ones. Clang builds with the same flags also crashed on unaligned messages. The API places no alignment requirement on the message; unaligned loads and an aligned `padded_block` avoid both crashes.

### Reproducing

```sh
sh hash-35/reproduce_sse_alignment.sh
```

## hash-35-5: The block-index tweak is encoded little-endian, not big-endian as specified

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Wish512 and Wish1024; reference implementation (the optimized implementations reproduce the same KATs)
Discovery: Moderate
Exploitation: An implementation that follows the specification computes a different digest for every message longer than one block; tweaks stay distinct, and no security consequence was identified
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance, in this candidate's specification notes of 2026-09-21; independently reported by Zhiqiang Yang, Lin Ao, Yue Li, Xin Yi, Ling Song and Lei Wang, using the CryptVerify tool (Cryptol and SAW)
Date: 2026-11-19
Follow-up source: [Yang et al.'s formal verification report, finding 8](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/7RGEIZ5TI5BTESVHWRVJMTQHX5CMYUB5/attachment/4/FormalVerificationReportonNGCCHashCandidates.pdf)

Section 3.3.2 (physical p. 6) defines the tweak of block i as τ_i = enc64(i) ‖ 0^64, where enc64 is "the big-endian 64-bit encoding of the block index", and Algorithm 2 line 5 XORs it into the state before every block. The reference `wish.c` (identical in both instances) writes `tweak[b] = (byte)(blk >> (b * 8))` (`:177–179`), which puts the least significant byte first. The two encodings agree only for block 0.

As shipped, both instances reproduce all 4,097 KAT_2_12 vectors. With only that line changed to the big-endian order, every single-block vector still matches and every longer one fails: 512 of 4,097 match for Wish512 and 1,024 for Wish1024.

### Reproducing

```sh
sh hash-35/reproduce_spec_mismatch.sh
```

The witness regenerates each KAT_2_12 file with the shipped NGCC generator and uses it only if its canonical SHA-256 equals the official file's entry in `hash-35/kat.sha256`.
