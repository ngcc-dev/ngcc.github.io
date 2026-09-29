<!-- synchronized report: hash-18/report.md -->
Candidate: MEGASCON
Family: Symmetric (sponge)
Archive: [Megascon.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Megascon.zip) (SHA-256: `70d0796942e60a1ddd25ad2332dbfe2755052825c301e9585167c90c1fa09d3d`)

## hash-18-1: For short messages, the 384-bit digest is a prefix of the 512-bit digest

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified construction and reference implementation, MEGASCON digest and XOF profiles
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Megascon team's revision notice](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/2VJXXVHAC7K44UFJ7YLSTJRSIWRJTVAQ/)

For the 24-bit message hex `616263` (`abc`), MEGASCON-384 returns:

`12a06f59d0c531c20cf4efad19195ba328c2aa92e8ef76b344f7084b98cc88a913f71388bb289e33b76accc9966d7cf4`

MEGASCON-512 returns that exact 48-byte value followed by:

`907761161784fcce7082995b14ee6036`

For every message shorter than 1024 bits, both variants initialize the same zero state, inject identical padded bytes at the same offset, and apply the same 15-round permutation. The digest length or variant identifier is never absorbed; only the amount returned to the caller differs.

The two functions therefore lack cross-variant domain separation and cannot be treated as independent hashes. No explicit specification claim of cross-profile independence was located, so this is reported as a confirmed composition defect rather than a collision-resistance claim violation.

The same missing domain separation affects the XOF profiles. On the audited short messages, the 384- and 512-profile 256-bit XOF outputs are equal, while shorter outputs are prefixes of the longer XOF streams. This follows from the normative zero initialization, common padding and permutation, and `MSB_l` output rule; it is not only a wrapper artifact.

The Megascon team subsequently assigned a distinct four-bit initialization domain to every digest and XOF profile and regenerated the specification, implementations, and KATs. That revision prevents the cross-profile state alignment; the frozen Round 1 archive remains affected.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C hash-18
tools/ngcc_attack hash-prefix hash-18/lib/libMEGASCON-384.so hash-18/lib/libMEGASCON-512.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## hash-18-2: The AVX-512 listing defines a noninjective S-box and practical collisions

Severity: High
Status: Confirmed
Layer: Design
Affected: AVX-512 computation printed in Listing 3; all four fixed-output profiles
Discovery: Moderate
Exploitation: Trivial
Credit: Cryptanalysts001 (ISCAS) <yufei2021@iscas.ac.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/J2WP5X7I7BHCONJCHMDD6ECLNV7D3XQ5/)
Follow-up source: [Megascon team's correction](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/2VJXXVHAC7K44UFJ7YLSTJRSIWRJTVAQ/)

Listing 3 uses ternary-logic immediates `b4` and `1e` with the wrong operand truth-table order. Its induced S-box has only 175 distinct outputs; in particular, `S_bad(23) = S_bad(24) = 1b`. A local collision can therefore be injected through the rate and makes the complete states equal after the second block's first substitution layer.

For MEGASCON-512, take two 256-byte messages initialized to zero, set `M[192] = 04`, and set `N[128] = N[160] = 04`. Under Listing 3, both hash to:

`2ed13b513054b271a9640e8ccc139d5a363cc69eee4158ec7453b6e39b3549a15a87b8695340271fdcb02903cfe42b79ea8227f074e05599299a318581faf368`

This is a specification-listing failure, not an attack on the archived implementations: the optimized code uses the corrected immediates `a6` and `56`, and the reference code implements the bijective mathematical S-box.

The Megascon team confirms that Listing 3 was a transcription error and replaces `b4`/`1e` by `a6`/`56` in its revised specification. This correction agrees with the already-correct submitted source.

### Reproducing

The local checker verifies the erroneous truth tables, the displayed collision inside the S-box, and bijectivity after correction:

```sh
python3 hash-18/validate_listing3.py
```

The complete-message collision above was independently evaluated in Python and scalar C by the reporters; no native AVX-512 execution is required or claimed.
