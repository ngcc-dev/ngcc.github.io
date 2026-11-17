<!-- synchronized report: hash-06/report.md -->
Candidate: Cuishen
Family: Symmetric (double-block-length Merkle–Damgård, ARX block cipher)
Archive: [Cuishen.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Cuishen.zip) (SHA-256: `b9192c8a4046d8af48ea19ddefd538f11dd456766b2daf3597762c76a2cc0d6d`)

## hash-06-1: Reduced-round differential figures are contradicted by probability-1 trails

Severity: Low
Status: Confirmed
Layer: Design
Affected: Specification §5.2.1, Cases 1, 2 and 4; all three instances
Discovery: Moderate
Exploitation: Collisions for every message pair of a fixed difference when Octarx is cut to 6 rounds (Cuishen-512) or 5 rounds (Cuishen-768, -1024); no effect on the full 64 rounds shown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

Section 5.2.1 (pp. 16–17) reports the best differential probabilities found for reduced-round Octarx and argues from their decay that 64 rounds are safe. For Case 1, a message-block difference with zero chaining difference before and after, it gives 2^-2, 2^-5 and 2^-13 for 4, 5 and 6 rounds of Octarx-256, and 2^-6 and 2^-16 for 4 and 5 rounds of Octarx-512.

Trails of probability 1 exist for those round counts. Each new word of the message register reaches a round key once, three rounds after it is made (`CryptHash_Cuishen-512.c:178-198`), and two round-key words feed the two addends of one addition (`:226`). Two message words that differ only in the top bit after rotation therefore cancel inside one round, and the difference stays out of the round keys for the next rounds. For Octarx-256 the differences 2^56 in word 12 and 2^43 in word 5 give zero state difference through 6 rounds; for Octarx-512 a four-word difference does the same through 5 rounds.

With the reference code's round loops cut to 6 rounds, Cuishen-512 gave full-digest collisions for 1,000 of 1,000 random message pairs with that difference; Cuishen-768 and Cuishen-1024 did the same at 5 rounds. A variant on bit 40 held for 497 of 1,000 pairs. One round more gave no collision, and neither did the full 64 rounds. Monte Carlo runs also contradict the Case 2 and Case 4 figures: 2^-3.2 at 6 rounds of Octarx-512 and 2^-3.0 at 7 rounds of Octarx-256, against stated bounds of 2^-14 and 2^-10.

The published figures understate what an attacker gets for free in the first 5 to 6 rounds, which is about 9% of the rounds. The decay argument was not re-derived from the corrected starting point, and no attack on more rounds was found.

### Reproducing

```sh
sh hash-06/reproduce_reduced_round_rk.sh
```

The witness builds the reference source with only the round count changed, first checks that 64 rounds reproduce the unmodified function, and then counts collisions at each reduced round count.
