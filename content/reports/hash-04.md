<!-- synchronized report: hash-04/report.md -->
Candidate: CHAMP
Family: Symmetric (Cayley graph / matrix products)
Archive: [CHAMP.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/CHAMP.zip) (SHA-256: `8953f95618236d8d86191992b10e3580ae74520c28a36a715c2fc8bea2a9e8c1`)

## hash-04-1: Palindrome messages reduce CHAMP collision bounds to 128 and 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: CHAMP-512 and CHAMP-1024 construction and all conforming implementations
Discovery: Non-trivial
Exploitation: At most 2^128 and 2^256 hash evaluations and stored records for greater-than-0.39 collision probability; no full-size collision computed
Credit: Jean-Philippe (JP) Aumasson (earlier fixed-length determinant distinguisher); collision and palindrome bounds by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

CHAMP hashes a bit string by multiplying two public `2 x 2` matrices. Both generators have determinant 2, so every message of a fixed bit length `n` has determinant `2^n`. All fixed-length outputs therefore lie in one determinant fiber of size exactly `p(p^2-1)`, approximately `p^3`, rather than the full approximately `p^4` matrix space.

Jean-Philippe (JP) Aumasson published a [known-length CHAMP-512 determinant distinguisher](https://gist.github.com/veorq/243ce3ecfd2ce5ab04dc0beadb69ead8) on 2026-09-20. It demonstrates this invariant; the collision bounds here are our extension.

An invertible output encoding cannot enlarge that image. A stronger restriction follows for palindromic messages. Let `Q=[[9,14],[14,22]]`. Both `AQ` and `BQ` are symmetric, so for every palindrome `M`, the product `H(M)Q` is symmetric and has fixed determinant `2^(|M|+1)`. Its image has at most `p²−p` elements for both submitted primes. Sampling `2^128` palindromes of 544 bits or `2^256` palindromes of 1056 bits therefore gives a same-length collision with probability above 0.39, independent of the output distribution; repeated inputs contribute less than `2^-17`. This is below the [NGCC-required](https://www.niccs.org.cn/niccs/Notice/crlRB1ZY.pdf) 256- and 512-bit collision levels. No full-size collision was computed. This palindrome extension was added on 2026-10-09.

Follow-up analysis: [Yufei Yuan, Ruichen Wu, Shanpeng Wei, Junxu Shen, Jinpeng Liu, and Yixin Zhang, *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/archive/2026/2152/20260923:103749), Sections 2.2 and 6 (2026-09-23), establish the earlier determinant-fiber collision bounds of `2^192` and `2^384`. The palindrome bounds above supersede those bounds; they are our further extension, not a result attributed to that paper.

### Reproducing

```sh
python3 hash-04/reproduce_structure.py
```

The exact-arithmetic certificate checks the generator and palindrome identities, the restricted image sizes, and a distribution-independent collision-probability bound. A separate internal check against compiles of the submitted reference C at both levels is recorded in `security/keccak_techniques/hash-04/h1_transpose_symmetry.py`; it is not part of the public command above. The full-size birthday search was not run.

## hash-04-2: Projective positive-word collision lead for CHAMP-512

Severity: Low
Status: Lead
Layer: Design
Affected: CHAMP-512 construction
Discovery: Non-trivial
Exploitation: Approximately 2^64 for CHAMP-512 (heuristic, not yet instantiated)
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Because `p = 7 mod 8`, 2 is a square. Scaling both generators by the inverse square root of 2 normalizes them into `SL2` without changing equal-length collisions. The exact generators satisfy `det(AB-BA)=2`, so they have no shared projective eigenline.

The Mullan-Tsaban general-generator heuristic then suggests positive-word collisions in approximately `sqrt(p)` work, around `2^64` for CHAMP-512. Its proven special case does not directly apply because `det(A-B)=-5`, so this remains a probable attack lead rather than a demonstrated collision. It should not be described as confirmed until instantiated against the exact generators.

### Reproducing

```sh
python3 hash-04/reproduce_structure.py
```

The certificate checks `det(A)=det(B)=2`, `det(A-B)=-5`, and `det(AB-BA)=2`. It explicitly does not instantiate the heuristic positive-word collision search.

## hash-04-3: Known-length preimages admit an exact square-root search

Severity: Critical
Status: Confirmed
Layer: Design
Affected: CHAMP-512 and CHAMP-1024
Discovery: Moderate
Exploitation: `O(2^(m/2))` time and storage; 2^256 for a 512-bit input and 2^512 for a 1024-bit input
Credit: Mounir IDRASSI <mounir@amcrypto.jp>
Date: 2026-09-22
Original source: [GitHub issue #7](https://github.com/ngcc-dev/ngcc-harness/issues/7)

Decode the public finalization of a target digest to obtain its matrix `T`, and split an `m`-bit candidate as `uv`. Store every `M(u)` for `floor(m/2)`-bit prefixes and search the suffixes for `T M(v)^-1`. The actual split of any target generated by an `m`-bit message guarantees a match, giving an exact meet-in-the-middle preimage search without a mixing or integer-lifting assumption.

For a uniformly sampled 512-bit input to CHAMP-512, this gives a preimage in `2^256` time and storage; for a 1024-bit input to CHAMP-1024, it costs `2^512`. Both are below the NGCC requirement of `h`-bit preimage security for an `h`-bit digest ([Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/crlRB1ZY.pdf) §1(2)), so the result is Critical even though these full-scale costs are infeasible. The submitted witness recovers a 40-bit input for both variants with two lists of about `2^20` products. It does not give a distinct second preimage or a full-parameter collision.

### Reproducing

The quick target uses 32-bit inputs; the full target repeats the submitted 40-bit experiment. Both generate and verify targets through the submitted C libraries and include a changed-input control:

```sh
make -C hash-04 reproduce
make -C hash-04 reproduce-full
```

## hash-04-4: Unsupported digest lengths cause full-size writes

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized CHAMP-512 and CHAMP-1024 implementations
Discovery: Trivial
Exploitation: Out-of-bounds write when a caller sizes the output for the requested length; no end-to-end corruption chain demonstrated
Credit: Mounir IDRASSI <mounir@amcrypto.jp>
Date: 2026-09-22
Original source: [GitHub issue #8](https://github.com/ngcc-dev/ngcc-harness/issues/8)

Every implementation explicitly discards `digest_len_bits`, returns success, and unconditionally writes the instance's complete 512- or 1024-bit digest. For example, requesting 256 bits from CHAMP-512 still writes 64 bytes; requesting 512 bits from CHAMP-1024 still writes 128 bytes. A caller allocating the output buffer from the requested length therefore receives a fixed 32- or 64-byte overflow.

The local reproducer allocates the full output plus a guard, proving the return value and write extent without itself writing out of bounds. It also verifies that the full result equals an ordinary full-length call and that the trailing guard remains intact. Fixed-output instances should reject every request unequal to `DIGEST_BIT_LENGTH` before writing.

### Reproducing

The guarded check is included in:

```sh
make -C hash-04 reproduce
```

## hash-04-5: Message bytes index a large precomputed matrix table

Severity: High
Status: Confirmed
Layer: Design
Affected: Reference CHAMP-512 and CHAMP-1024
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The absorption loop selects `byte_table[(unsigned char)msg[i]]` directly from each message byte (`CryptHash_AlgorithmInstance.c:279` in CHAMP-512; `:308` in CHAMP-1024). Entries contain four field elements and occupy distinct cache lines. The memory-address trace therefore reveals every absorbed byte to an observer able to distinguish table lines. Field reduction and inverse dispatch also branch on secret-dependent state. No end-to-end cache-extraction experiment was run. See [constant_time.md](../constant-time/hash-04.md).

Constant-time fix (hard, hence High and Design): the design's speed comes from indexing a 256-entry table of precomputed matrix products by each message byte. A constant-time version must scan the whole table with a masked select for every byte or build each byte's matrix from eight per-bit products, and field reduction and inversion need branch-free forms. We estimate this makes absorption several times slower. No competitive constant-time path is supplied or known, so the leakage is a property of the specified design rather than of this code.

### Reproducing

Inspect the cited table access. For equal-length first-byte choices `0x00` and `0x80`, the first table addresses differ by 128 entries; the two inputs differ only in secret content.
