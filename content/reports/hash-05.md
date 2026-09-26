<!-- synchronized report: hash-05/report.md -->
Candidate: uHash
Family: Symmetric (block-cipher-based hash)
Archive: [uHash.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/uHash.zip) (SHA-256: `c398e49530510c9aa1deffd617855f9b8db448b4e30a35953d88ea0373c7d8e5`)

## hash-05-1: Secret state indexes a 256-byte substitution table

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference uHash-512/768/1024
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The reference `RoundFunction` xors the evolving state with a round key, then reads `S[X[i]]` and `S[Y[i]]` (`CryptHash_AlgorithmInstance.c:163-174`). `S` contains 256 bytes (`:36`), spanning cache lines. Equal-length messages can therefore select different lookup addresses during hashing. No complete message-recovery experiment is claimed. See [constant_time.md](../constant-time/hash-05.md).

### Reproducing

Inspect the cited table accesses in any reference variant. The lookup indices are the evolving `P[i] ^ RK[i]` bytes, not public counters.

## hash-05-2: Narrow-pipe iteration limits uHash second-preimage security for long messages

Severity: Medium
Status: Confirmed
Layer: Design
Affected: uHash-512, uHash-768 and uHash-1024 specifications and implementations
Discovery: Trivial
Exploitation: About 2^h / l compression calls for an l-chunk target: approximately 2^457.6, 2^713 and 2^968 at the required 2^64-bit message length
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-26

uHash claims that "the classical security against preimage and second-preimage attacks is no less than h bits" (abstract, physical PDF page 1; Table 9, page 11), which a long-message attack violates.

The chaining value is exactly h bits wide (Algorithm 1, page 4). Padding is `M ∥ 1 ∥ 0*` with no length field (§1.2.1, page 4; `Padding`, `CryptHash_AlgorithmInstance.c:441-474` in the uHash-512 reference source). Intermediate compression calls take no block index; only the final call is tweaked (`:526`, `:578-586` in that source). The uHash-768 and uHash-1024 reference sources follow the same structure. An attacker tries one-chunk prefixes until the chaining value equals any intermediate chaining value of an l-chunk target, then appends the rest of the target. The expected cost is 2^h / l compression calls. The specification requires messages of up to 2^64 − 1 bits (page 3), so the cost falls to about 2^457.6, 2^713 and 2^968 for the three sets. The specification's own proof bounds the second-preimage advantage by (b + l)q / 2^h (§3.2.2, page 14), which is consistent with this loss but not with the flat h-bit claim.

### Reproducing

Compare the claim on physical PDF pages 1 and 11 with the padding and iteration in Algorithm 1 (page 4) and at the cited source lines.

## hash-05-3: Unused partial-byte bits cancel padding and give trivial collisions

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized uHash-512/768/1024 bitstring-input paths
Discovery: Trivial
Exploitation: Immediate full-round collision; no search required
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-26

The API accepts a message pointer and its length in bits, using the most-significant bits of a partial byte. Bits after that declared length are not part of the message, and the supplied API instructions impose no precondition that callers zero them. The specification pads the bitstring injectively as `M ∥ 1 ∥ 0*` (§1.2.1 and §2.2), but `Padding` copies the caller's entire partial byte and **adds** the pad bit without first masking the unused bits (`CryptHash_AlgorithmInstance.c:442-463`; optimized implementation `:6178-6199`).

This gives deterministic collisions between distinct bitstrings. The one-bit message `0`, supplied as byte `00` with length 1, is padded to byte `40`. The two-bit message `00`, supplied as byte `20` with length 2, is also padded to `40`: the `20` bit is outside the declared two-bit message and the implementation adds the two-bit padding marker `20`. The complete padded inputs are identical, so all subsequent full-round computation is identical. The submitted uHash-512, uHash-768 and uHash-1024 libraries all return equal digests for this pair; canonical encoding of the two-bit message and a changed meaningful bit are non-colliding controls.

The collision requires nonzero unused bits in the caller's final byte. Canonically encoded inputs do not collide under this witness, which limits its severity to High; `hash-09-1` does not have that input-encoding precondition.

The implementation must mask the unused low bits before setting the padding bit, for example `M[k] = (msg[k] & (0xff << (8-r))) | (1 << (7-r))` for `r = msg_len_bits mod 8`.

### Reproducing

```sh
make -C hash-05 exploit
```

The witness checks the collision and both controls through every submitted reference-library API and prints three `ATTACK hash-05-3 ... CONFIRMED` lines.
