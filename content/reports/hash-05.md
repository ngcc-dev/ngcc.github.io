<!-- synchronized report: hash-05/report.md -->
Candidate: uHash
Family: Symmetric (block-cipher-based hash)
Archive: [uHash.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/uHash.zip) (SHA-256: `c398e49530510c9aa1deffd617855f9b8db448b4e30a35953d88ea0373c7d8e5`)

## hash-05-1: Secret state indexes a 256-byte substitution table

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference uHash-512/768/1024
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The reference `RoundFunction` xors the evolving state with a round key, then reads `S[X[i]]` and `S[Y[i]]` (`CryptHash_AlgorithmInstance.c:163-174`). `S` contains 256 bytes (`:36`), spanning cache lines. Equal-length messages can therefore select different lookup addresses during hashing. No complete message-recovery experiment is claimed. See [constant_time.md](../constant-time/hash-05.md).

Constant-time fix (easy, hence Low): the specified uBlock S-box is 4-bit, so the merged 256-byte table can be replaced by a 16-entry in-register `pshufb` lookup or a bitsliced circuit, the implementation style uBlock was designed for.

### Reproducing

Inspect the cited table accesses in any reference variant. The lookup indices are the evolving `P[i] ^ RK[i]` bytes, not public counters.

## hash-05-2: Narrow-pipe iteration limits uHash second-preimage security for long messages

Severity: Critical
Status: Confirmed
Layer: Design
Affected: uHash-512, uHash-768 and uHash-1024 specifications and implementations
Discovery: Trivial
Exploitation: About 2^h / l compression calls for an l-chunk target: approximately 2^457.6, 2^713 and 2^968 at the required 2^64-bit message length
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-26
Follow-up source: [Bishwajit Chakraborty's 2026-10-11 CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/ZMFQ4OFLGKGVI6U7ACKWKDVAZUEPN4YA/)

uHash claims that "the classical security against preimage and second-preimage attacks is no less than h bits" (abstract, physical PDF page 1; Table 9, page 11), which a long-message attack violates.

The chaining value is exactly h bits wide (Algorithm 1, page 4). Padding is `M ∥ 1 ∥ 0*` with no length field (§1.2.1, page 4; `Padding`, `CryptHash_AlgorithmInstance.c:441-474` in the uHash-512 reference source). Intermediate compression calls take no block index; only the final call is tweaked (`:526`, `:578-586` in that source). The uHash-768 and uHash-1024 reference sources follow the same structure. An attacker tries one-chunk prefixes until the chaining value equals any intermediate chaining value of an l-chunk target, then appends the rest of the target. The expected cost is 2^h / l compression calls. The specification requires messages of up to 2^64 − 1 bits (page 3), so the cost falls to about 2^457.6, 2^713 and 2^968 for the three sets. The specification's own proof bounds the second-preimage advantage by (b + l)q / 2^h (§3.2.2, page 14), which is consistent with this loss but not with the flat h-bit claim.

Chakraborty's later forum post identifies the same long-message loss and gives rounded costs of `2^458`, `2^713` and `2^968`; it does not require a separate finding.

### Reproducing

Compare the claim on physical PDF pages 1 and 11 with the padding and iteration in Algorithm 1 (page 4) and at the cited source lines.

## hash-05-3: Unused partial-byte bits cancel padding and give trivial collisions

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized uHash-512/768/1024 bitstring-input paths
Discovery: Trivial
Exploitation: Immediate full-round collision; no search required
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-26

The API accepts a message pointer and its length in bits, using the most-significant bits of a partial byte. Bits after that declared length are not part of the message, and the supplied API instructions impose no precondition that callers zero them. The specification pads the bitstring injectively as `M ∥ 1 ∥ 0*` (§1.2.1 and §2.2), but `Padding` copies the caller's entire partial byte and **adds** the pad bit without first masking the unused bits (`CryptHash_AlgorithmInstance.c:442-463`; optimized implementation `:6178-6199`).

This gives deterministic collisions between distinct bitstrings. The one-bit message `0`, supplied as byte `00` with length 1, is padded to byte `40`. The two-bit message `00`, supplied as byte `20` with length 2, is also padded to `40`: the `20` bit is outside the declared two-bit message and the implementation adds the two-bit padding marker `20`. The complete padded inputs are identical, so all subsequent full-round computation is identical. The submitted uHash-512, uHash-768 and uHash-1024 libraries all return equal digests for this pair; canonical encoding of the two-bit message and a changed meaningful bit are non-colliding controls.

The collision requires nonzero unused bits in the caller's final byte, but the API assigns no meaning to those bits and imposes no requirement that callers clear them. The two declared bitstrings are therefore distinct valid inputs. This immediate collision violates the NGCC requirement of at least `h/2`-bit collision security ([Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/crlRB1ZY.pdf) §1(2)) and is Critical. Canonically zeroed backing bytes avoid this particular witness but do not repair the API implementation.

The implementation must mask the unused low bits before setting the padding bit, for example `M[k] = (msg[k] & (0xff << (8-r))) | (1 << (7-r))` for `r = msg_len_bits mod 8`.

### Reproducing

```sh
make -C hash-05 exploit
```

The witness checks the collision and both controls through every submitted reference-library API and prints three `ATTACK hash-05-3 ... CONFIRMED` lines.

## hash-05-4: Final-block counter cancellation lets 2 to 4 chosen queries predict unqueried continuations

Severity: High
Status: Confirmed
Layer: Design
Affected: uHash-512, uHash-768 and uHash-1024 specification; reference and optimized implementations
Discovery: Moderate
Exploitation: 2, 3 or 4 chosen queries under an unknown chunk-aligned prefix recover the full chaining value and predict unqueried continuations on all three submitted libraries; no collision, preimage or second preimage
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

uHash separates the final iteration from the ordinary compression function only by XORing a branch counter into the key (Algorithm 1, line 14, physical PDF page 4; §1.2.5, page 6). The key is `u^2 ∥ … ∥ u^b ∥ M_l`, so the counter lands in the last byte of the final message chunk. The submitted code uses the counters `15, …, 14+b` for branches `j = 0, …, b−1`: `0x0f, 0x10` for uHash-512 (`CryptHash_AlgorithmInstance.c:578,586`), `0x0f, 0x10, 0x11` for uHash-768 (`:749-763`) and `0x0f … 0x12` for uHash-1024 (`:962-969`). Read literally, the specification's `j+15` with `j = 1, …, b` is one larger. Every counter is a nonzero byte under either indexing, so the attack below works for both. The optimized trees, which are Windows-only AVX2 code, implement the same final iteration separately in `CF_512_Final`, `CF_768_Final` and `CF_1024_Final` (`:980`, `:2861`, `:5062`).

Padding is `M ∥ 1 ∥ 0*` (§1.2.1, page 4), so a valid final chunk can end in any nonzero byte. Let `Z` be any chunk ending in `00`, and let `Z_j` be `Z` with its last byte replaced by the counter `c_j` of branch `j`. In the final iteration on `Z_j`, branch `j`'s counter cancels the message byte, so digest branch `j` of `X ∥ Z_j` equals branch `j` of the ordinary compression `CF(u, Z)`.

Taking branch `j` from the digest of query `X ∥ Z_j`, for `j = 0, …, b−1`, gives the complete chaining value after `X ∥ Z`. The attacker never needs the prefix `X`, which can be any secret whole number of chunks. Public evaluation of uBlock-1024 then gives `uHash(X ∥ Z ∥ W)` for any continuation `W`. This takes `b = 2, 3, 4` chosen queries and `b` cipher calls per final chunk, plus one query to check the prediction, and it succeeds with probability 1. Against a random oracle the success probability is about `2^-h`. For example, a secret-prefix MAC `uHash(K ∥ m)` with a chunk-aligned key is forgeable after `b` chosen-message queries.

This contradicts the specification's length-extension argument (§3.3.1, page 22), which relies on the digest not being an intermediate chaining value. Here the intermediate chaining value is assembled from `b` related digests. It also contradicts the 256/384/512-bit indistinguishability claims (§3.1 and Table 9, page 11; simulator proof in §3.2.4, page 15). A simulator never sees `X`, so it cannot answer the distinguisher's `b` cipher queries consistently with the random oracle on the unqueried message. The NGCC call does not require length-extension resistance, so this is a High violation of an additional claimed property rather than a Critical break. The relation needs chosen queries that share the prefix. It does not extend a single known digest, and it gives no collision, preimage or second preimage.

### Reproducing

```sh
python3 hash-05/reproduce_final_counter_extension.py
```

For each submitted reference library, the script first checks a pure-Python transcription of uBlock-1024 and the uHash mode against the library on six message lengths. It then hides a random one- or two-chunk prefix behind a query interface, recovers the chaining value from `b` queries, and predicts two unqueried continuations, one ending in a short tail and one with an extra full chunk. Controls run the same attack against an ideal random function and with a non-cancelling final byte `80`, and both must mispredict. The run takes under one second. The optimized trees were inspected but not built or run.
