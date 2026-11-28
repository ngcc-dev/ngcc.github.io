<!-- synchronized report: hash-09/report.md -->
Candidate: Eijen
Family: Symmetric (sponge, Sponge-F)
Archive: [Eijen.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Eijen.zip) (SHA-256: `5e2581d905b9a3d3a8c34c76ed73213c77da970a15cc6b3b26b2bb086b93e3f4`)

## hash-09-1: Trivial collisions in all Eijen implementations

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized implementations, all five parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The following collision was verified against Eijen-256:

- Input 1: empty string, length 0 bits
- Input 2: hex `00`, length 7 bits (seven zero bits)

Both produce:

`6f13fcc5cb0edcc73d8129c78913b663b5c6040fa0e2e8c4819d16b0ffda051d`

The bit length is essential: hex `00` with length 8 bits is a different message.

The collision comes from mixing two bit-order conventions. For a byte-aligned message, the implementation writes `0x01`, following the specification's LSB-first worked example: physical PDF pages 24–25 encode padded `abc` as the bytes `61 62 63 01 ...`. The submitted KATs depend on this convention.

For a partial final byte, however, the implementation uses `0x80 >> partial_bits`, following the uniform API's MSB-first convention for significant bits. After seven explicit zero bits this path also writes `0x01`, so the distinct messages have identical padded representations.

More generally, for every byte-aligned message `M`, `H(M) = H(M || 0^7)`. The defect affects all five submitted parameter sets. Simply replacing byte-aligned `0x01` with `0x80` would change every byte-aligned digest, contradict the specification's worked example, and break the KATs. Repair requires one consistent bit-order convention across the specification, API, implementation, and test vectors, with an injective encoding for every bit length.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C hash-09
tools/ngcc_attack hash-collide-zeropad hash-09/lib/libEijen-256.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## hash-09-2: Cross-instance three-block relations

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified Eijen-512, Eijen-768, and Eijen-1024 construction
Discovery: Moderate
Exploitation: Moderate
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/3KZDO7FTB6ELVWL2ILGNXP256XCJBBES/)
Follow-up source: [Eijen Algorithm Group's response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/LZYIEYXZWH7LADLHM64NH2G4MDTOQ6DK/)

The three instances use the same 2048-bit permutation and zero initial state, with only the rate and capacity-feed-forward boundary changing. The reporters constructed three-block message pairs whose outputs obey a predictable cross-instance suffix relation, succeeding on 8/8 trials for every pair of instances. This distinguishes the family from independent random functions, but is not a same-instance collision or a direct break of an individual instance's collision resistance.

The Eijen Algorithm Group independently confirmed the issue. The original public message does not include its concrete three-block witnesses, so that particular construction has not been locally replayed.

Follow-up analysis: the [Iphe Algorithm Group's cross-rate note, posted by 崔灏睿 on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BWXG6OPAIQL32FMWWYJ3C4D6QMRGHGP4/), identifies a simpler one-block relation in the archived implementation. For the same message shorter than 960 bits, the Eijen-512 digest is the final 512 bits of both Eijen-768 and Eijen-1024. The submitted libraries confirm this for the empty message, `abc`, and a 119-byte test message, with changed-message controls differing. This is still a cross-instance relation, not a same-instance collision.

### Proposed fixes

The [Eijen Algorithm Group's response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/LZYIEYXZWH7LADLHM64NH2G4MDTOQ6DK/) proposes injecting the digest length during finalization. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C hash-09 lib/libEijen-512.so lib/libEijen-768.so lib/libEijen-1024.so
python3 hash-09/reproduce_cross_instance_suffix.py
```

## hash-09-3: The specified final-block feed-forward includes the constant 1_c, but the code and the specification's own test vectors omit it

Severity: Low
Status: Confirmed
Layer: Design
Affected: Eijen-256, -384, -512, -768 and -1024; specification §2.3 against Appendix B, the reference and optimized implementations and the KATs
Discovery: Moderate
Exploitation: An implementation of the §2.3 formulas computes, for every message, a digest that differs in exactly one bit from the submitted code and from the Appendix B vectors; the difference is a constant and has no security consequence
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance, in this candidate's specification notes of 2026-09-21; independently reported by Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, using MechCrypto
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/hash-function/hash-09_Eijen)

Section 2.3 (physical p. 6) defines the last absorption as `S = X ⊕ (M ‖ 1_c)` followed by `X' = Π(S) ⊕ (0^r ‖ right_c(S))`. The capacity that is fed forward therefore contains the constant `1_c`.

The reference `eijen_absorb_block` saves the capacity first (`eijen_ref.c:105–107`), then adds the constant as bit 63 of the last state word (`:111–113`), and XORs the saved capacity after the permutation (`:117–119`). The value fed forward lacks `1_c`. The last state word is part of every digest, so the code returns the specified digest with one bit flipped: the top bit of the last 64-bit word. The file is identical in the five instance directories, and `eijen_avx2.c:178–190` has the same order.

An independent model of §2.3 and §2.4 was compared with the five reference libraries on 90 byte-aligned messages of 0 to 1,000 bytes. With the code's order of operations it reproduces every digest. With the formula of §2.3 it differs in exactly that bit each time. For "abc", the Appendix B vectors (physical pp. 24–29) for Eijen-256, -384, -512 and -1024 equal the library output and end in byte `86`; the formula gives `06`. The formula therefore contradicts the specification's own vectors, and the code follows the vectors.

### Reproducing

```sh
pdftotext -f 6 -l 6 -layout hash-09/hash-09-spec.pdf - | grep -n "rightc (S"
sed -n '99,120p' hash-09/Eijen/Implementations/Reference_Implementation/Eijen-512/eijen_ref.c
```

This is a source witness. The model comparison is not part of it.
