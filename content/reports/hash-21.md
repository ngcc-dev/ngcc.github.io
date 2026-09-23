<!-- synchronized report: hash-21/report.md -->
Candidate: Neulaser
Family: Symmetric (PRNG-based iterated hash)
Archive: [Neulaser.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Neulaser.zip) (SHA-256: `ffa76faaf6ae1c939ef6b1a726d6bcef19f0f0df63daddfe74a82e2831c4c6b3`)

## hash-21-1: A local feedback collision merges complete Neulaser states

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Neulaser-512, Neulaser-768, and Neulaser-1024
Discovery: Moderate
Exploitation: Trivial after a 175,493-input local search
Credit: Cryptanalysts001 (ISCAS) <yufei2021@iscas.ac.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/ENAQP4ZG7BMA4R4VTSXAWS74ARE7D7SX/)

For a register module whose only nonzero word is its discarded first stage, the feedback map sends both `00002743` and `0002ad84` to `8c41db68`. The global mixing function does not read that stage, so states differing only by these words become identical after one initialization round. All later rounds and the final digests are then identical.

The reporters give equal-length fixed-IV messages `00^d || BE32(x) || 00^60`, with `d=56,88,120` bytes for the three instances and `x` chosen from the colliding pair. The submitted Neulaser-512 implementation maps both 120-byte messages to `f899bf50663e6e04fa5374baf28886153ea332bf25443817eb2abbca88072458dbd7a077712aae99fb112b7672c85a705700e027b348516cc45f8fff537713d3`; full-round collisions reproduce for all three instances.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/2026/2152), Section 4 (2026-09-23), derives this local-feedback collision and its fixed-IV message pairs. It does not address the separate `hash-21-2` mechanism below.

## hash-21-2: Reduction modulo 2^32-5 creates reachable state mergers

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Neulaser-512, Neulaser-768, and Neulaser-1024
Discovery: Moderate
Exploitation: Trivial
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/XQYQ4KEDXJKCSRQT6DY5XNA4WIHGJB4J/)

Neulaser loads unrestricted 32-bit message words but overwrites stages 8, 12, and 15 after reduction modulo `p=2^32-5`. Each value `y` from 0 through 4 therefore has two encodings, `y` and `y+p`. Stages 8 and 12 do not enter any other tap feeding that round, so choosing the two pre-reduction values makes the entire state merge after one round.

The public comment supplies deterministic one-block collisions for every parameter set. For Neulaser-512, two otherwise-zero 888-bit messages place `45d27672` and `ba2d8989` at bytes 24--27; both produce the published digest beginning `a4cfaefc283b5d78`. Four independently mergeable words give 16-message multicollisions. This is a second, independent full-round collision mechanism, not a restatement of `hash-21-1`.

### Reproducing

The witness verifies both published collision families, including the exact full digests, against all three submitted libraries:

```sh
make -C hash-21 reproduce
```

## hash-21-3: Secret state indexes a 256-byte S-box

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference Neulaser-512/768/1024
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

`nl_sbox_word` reads `NL_SBOX` at four indices derived from an evolving 32-bit state word (`CryptHash_AlgorithmInstance.c:85-90`). The 256-byte table spans cache lines, so the lookup address depends on secret message content. The source also computes state-derived `x % (2^32-5)` (`:60-63`), whose timing requires target-specific code inspection; the report does not rely on it. No preimage-recovery exploit is claimed. See [constant_time.md](../constant-time/hash-21.md).

### Reproducing

Inspect the four `NL_SBOX` accesses in any reference variant and compare indices for unequal state words; they select different table lines.
