<!-- synchronized report: hash-11/report.md -->
Candidate: Garnet
Family: Symmetric (AES-derived hash)
Archive: [Garnet.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Garnet.zip) (SHA-256: `9cb659f7e01a64bdcce2a4fea8a7d6e6b5687b2a0ed8ce4ffe5fa86dd3e77646`)

## hash-11-1: Secret state indexes AES T-tables

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference Garnet variants
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Each AES-like round indexes four 1-KiB T-tables with bytes of the evolving hash state (`Garnet_1024.c:278-281`; `Garnet_512.c:322-325`). These indices depend on the message and select different cache lines, exposing state-dependent memory addresses in a shared-cache setting. A two-entry reduction table is also indexed by a state bit. No preimage-recovery exploit is claimed. See [constant_time.md](../constant-time/hash-11.md).

Constant-time fix (easy, hence Low): the round is an AES round, so use the AES instruction (`aesenc`, or ARMv8 `aese`/`aesmc`) as the specification intends, and a `pshufb` vector-permute or bitsliced AES where it is unavailable. The two-entry reduction table becomes a mask.

### Reproducing

Inspect the cited `TE0`–`TE3` loads; identical-length inputs with different first blocks produce different state-derived table indices. This is an address-trace witness, not a timing-extraction benchmark.

## hash-11-2: Garnet-1024a omits the specified rate-state feed-forward

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference `Garnet_1024.c` (Garnet-1024a); the optimized assembly was not checked
Discovery: Moderate
Exploitation: The stated Sponge-DM bound does not cover the submitted reference function; no collision or preimage attack is demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-09

The specification defines each Sponge-DM absorption as `X = S xor I_r(M)` and `S' = P^12(X) xor X` (§2.5 and Proposition 2, physical pp. 9–10). Proposition 2 explicitly relies on this *full-state* feed-forward. The reference code instead saves only the old capacity, absorbs the message, permutes, then XORs the message and saved capacity (`Garnet_1024.c:665–682, 820–829, 868–873`). Its update is `S' = P^12(X) xor I_r(M) xor (0_r || S_c)`, omitting the old rate state `S_r`. The formulas differ by `I_r(S_r)`.

The native witness checks the difference against the submitted reference functions, including a zero-rate-state control where the formulas agree. A separate local model/KAT check, not part of this reproducer, found that the code's empty-message digest matches its KAT while the specified feed-forward gives a different digest. This is a conformance and proof-applicability gap, not evidence that the implemented hash misses a collision or preimage target.

### Reproducing

```sh
python3 hash-11/reproduce_dm_feedforward.py
```

## hash-11-3: 32-bit byte counts give collisions between 4 GiB messages and crash on 2 GiB messages

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Garnet-512 (all five rate files), Garnet-768 and Garnet-1024 reference implementation; the additional implementation has the same counts by source
Discovery: Trivial
Exploitation: Two different messages of 2^35 + 128 bits collide at Garnet-512 when they agree in their first 16 bytes, and at Garnet-1024 when they differ only in byte 16; 2 GiB messages crash every instance
Credit: LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool; Garnet-768 and -1024 collisions by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19
Original source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/AS7TAC22MG7IN3CLQCJF647S33ZTDZ2L/)

`pad_message` keeps the message byte count in an `int`, and the absorption loops compare against `(int)byte_num` (`Garnet_512_896.c:578,606,664,682`; the same in the other four 512-bit rate files). At 2^35 + 128 bits (2^32 + 16 bytes) the count wraps to 16, so Garnet-512 absorbs only bytes 0 to 15 followed by the true 64-bit length: messages of that length that agree in their first 16 bytes collide. Garnet-768 and -1024 write their padding at the wrapped offset 16 of the message copy (`Garnet_768.c:671,699`, `Garnet_1024.c:698,726`), so with GCC at `-O2` two Garnet-1024 messages that differ only in byte 16 collide. When the `int` loop counters of those two instances wrap (GCC with `-fwrapv` or without optimization), only the first 2^31 bytes are absorbed; Garnet-768 at plain `-O2` aborts or crashes instead. At 2^34 + 128 bits the count is negative and `pad_message` writes before the buffer, crashing all three sizes.

With GCC at `-O2`, two such Garnet-512 messages differing in bytes 16 and 79, a middle byte and the last byte collided at the 896- and 512-bit rates (and, in separate runs, at the other three), while their 128-bit prefix and 1 KiB controls did not. The additional `hash_garnet_universal.c` uses the same `int` count. It does not compile against the submitted header as shipped (`:1327` drops the `const` of `CryptHash_Garnet.h:37`); built anyway, it pads and byte-reverses the caller's buffer in place (`:1340,1344`), writing one byte past a byte-aligned message.

### Reproducing

```sh
sh hash-11/reproduce_long_message_collision.sh
```

Each call copies the message, so the witness needs about 10 GiB of free memory (it skips with less) and takes about 1.5 minutes.

## hash-11-4: Absorbed block count and length injection differ from the specification

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Garnet-512 at all five rates, Garnet-768 and Garnet-1024; reference implementation
Discovery: Moderate
Exploitation: An implementation that follows the specification computes different digests: at the boundary lengths for the block count, and for every non-empty message for the length injection; the encoding stays injective, and no security consequence was identified
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance, in this candidate's specification notes of 2026-09-21; independently reported by Zhiqiang Yang, Lin Ao, Yue Li, Xin Yi, Ling Song and Lei Wang, using the CryptVerify tool (Cryptol and SAW)
Date: 2026-11-19
Follow-up source: [Yang et al.'s formal verification report, findings 9 and 10](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/7RGEIZ5TI5BTESVHWRVJMTQHX5CMYUB5/attachment/4/FormalVerificationReportonNGCCHashCandidates.pdf)

Eq. (1) (§2.2, physical p. 4) pads M to m = ⌊mlength/128⌋ + 1 words of 128 bits, and eq. (2) (§2.5, p. 8) groups them into rate-sized blocks, so ⌈128m/r⌉ blocks are absorbed (p. 9). The code counts `byte_num = ⌈mlength/8⌉` message bytes, absorbs ⌊`byte_num`/W⌋ full blocks and then always absorbs one more (`Garnet_512_640.c:658–709` at r = 640, and the same in the other files). When mlength mod r lies in {r − 7, …, r − 1}, the padding bit already sits in the last full block, and the extra block is all zero. With the specified count the shipped code fails exactly at those lengths, 28 to 56 of the 4,097 KAT_2_12 vectors per variant.

After the last block, §2.5 (pp. 9–10) injects mlength "into the rate part in the same serialized convention", which §2.2 (p. 4) defines as the first 128-bit word going to the lowest-numbered rate word. The code XORs the same word into S0, S5, S10 and S15 (`absorb_message_4x4`). With the length XORed into S0 only, every variant matches only the empty message. The specification does not state the word's width or byte order, but no reading of it places four copies.

As shipped, every variant reproduces all 4,097 vectors.

### Reproducing

```sh
sh hash-11/reproduce_spec_mismatch.sh
```

The witness regenerates each KAT_2_12 file with the shipped NGCC generator and uses it only if its canonical SHA-256 equals the official file's entry in `hash-11/kat.sha256`.
