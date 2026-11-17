<!-- synchronized report: hash-28/report.md -->
Candidate: The XRH-1 Hash Function
Family: Symmetric (SPONGE-EDMc, wide-trail permutation)
Archive: [XRH-1.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/XRH-1.zip) (SHA-256: `0aa9a5a64a54ddaa82b689d46971973825e48e0577685317d5f9bbab9ba85b02`)

## hash-28-1: Message lengths within one rate of 2^64 give a constant digest in the reference implementation

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: XRH-1-512, -768 and -1024 reference implementation; the AVX2 implementation behaves differently in this range
Discovery: Moderate
Exploitation: For a declared length in the top r values below 2^64 the digest does not depend on the message; such a message needs 2^61 bytes, so the case is not reachable in practice
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

The reference `CryptHash` loops over `(msg_len_bits + state.rate_bits) / state.rate_bits` blocks (`CryptHash_AlgorithmInstance.c:263`). For every `msg_len_bits` from 2^64 − r to 2^64 − 1 the sum wraps and the count is zero. Nothing is absorbed, the padding is not applied and the message is never read; the digest is the squeeze of the all-zero state. With r of 704, 448 and 192 bits for the three instances, that many lengths share one digest, which starts with zero bits. The specification's algorithm has no length limit, and the call requires messages of up to 2^64 − 1 bits.

The witness passes an inaccessible page as the message, so any read would fault, and obtains the same digest for four lengths in the range at each instance, different from the digest of the empty message. GCC and Clang builds agree. The AVX2 implementation's loop is written differently and keeps reading in this range, so the two trees disagree there.

The same expression multiplies `state.rate_bits*i` in `size_t` (`:264,269`). On a target with a 32-bit `size_t` this would misplace the final block for messages of 2^32 bits or more; that was only simulated, not built.

### Reproducing

```sh
sh hash-28/reproduce_lenwrap.sh
```

## hash-28-2: Two statements in the permutation analysis are contradicted by computation

Severity: Low
Status: Confirmed
Layer: Design
Affected: Specification §3.1.2 and §3.1.3 (XRH-p, shared by XRH-1 and XRH-2)
Discovery: Moderate
Exploitation: None on the full 18 rounds; the statements concern reduced-round distinguishers used to argue the margin
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

Section 3.1.2 (p. 21) reports that "no 5-round impossible differential distinguisher exists for XRH-p when both the input and output differences contain only one active cell". Every such pair is impossible over 5 rounds. One active cell spreads to exactly 16 active columns in two forward rounds with probability 1, while one active output cell requires all 64 columns active three rounds earlier, so the two cannot meet. This holds for all 3 × 256 × 256 position pairs at each of the three round alignments, by exact propagation and by a truncated SAT model, and 2,000 random pairs of the shipped permutation behaved as predicted. The same truncated-difference search found no single-cell pair that is impossible over 6 rounds; that is a search result in that model, not a proof that none exists.

Section 3.1.3 states that n rounds have degree at most 2^n and the inverse at most 3^n, "the same as SHA-3". A round of XRH-p applies the S-box layer twice, so one round has degree 4 and its inverse degree 9; cube sums of the shipped permutation are non-zero at dimension 3 after one round. The 16-round zero-sum the section derives from the stated bounds therefore does not follow as written.

Neither statement is a security claim, and the specification does not rule out full-round zero-sums. The first understates what a 5-round distinguisher achieves, against the 9 rounds of each half of XRH-1's absorbing function; the second gives a lower degree than the permutation has. No attack on more rounds follows.

### Reproducing

```sh
sh hash-28/reproduce_spec_claims.sh
```

The witness links the shipped `XRH1280` permutation and checks the propagation patterns and the one-round cube sums.
