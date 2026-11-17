<!-- synchronized report: hash-12/report.md -->
Candidate: Iphe
Family: Symmetric (Sponge-F hash)
Archive: [Iphe.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Iphe.zip) (SHA-256: `42ceda5aa3da2fc74c2b21abfaace3f5af208aab40ef00fcca6d18cdd7a0a844`)

## hash-12-1: Cross-profile 512-bit output relation

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Archived Iphe-512 and Iphe-1024 construction and reference implementations sharing the zero IV
Discovery: Moderate
Exploitation: Trivial
Credit: Iphe Algorithm Group <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-23
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/4WP4A2LYRID7X3OA76SV4PLXVXW2LVHZ/)

The Iphe Algorithm Group reported this relation on 2026-09-22. The archived profiles use the same permutation and zero initial state but have 960- and 1472-bit rates. In three-block transcripts, the first block can produce a common state, while the second creates a known difference only in the 512-bit rate/capacity boundary gap. Compensating for that difference in the third Iphe-512 message block makes the final permutation inputs equal. The capacity feed-forward then leaves output words 23–30 equal, giving a constructed pair with `suffix_512(Iphe-1024(M)) = Iphe-512(M')`.

Further extension to the Iphe Algorithm Group's analysis: the local witness finds padding-compatible blocks after seven trials and confirms the relation through both submitted `CryptHash` libraries on 2878- and 4414-bit messages. A one-bit changed-message control does not satisfy it. This is a cross-profile distinguisher, **not** a collision or preimage attack against either profile alone.

The report applies to the archived, SHA-256-pinned submission.

Follow-up analysis: the [group's cross-rate note, posted by 崔灏睿 on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BWXG6OPAIQL32FMWWYJ3C4D6QMRGHGP4/), gives the general feed-forward construction and an independent full-round Iphe witness. Its distinct-IV caveat agrees with the revised-profile scope above.

### Proposed fixes

The [Iphe Algorithm Group's follow-up](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/3NHT6MB6FTPF63JO7YXX3Y6HH422SQGC/) proposes distinct IVs for the two profiles. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C hash-12 lib/libIphe-512.so lib/libIphe-1024.so
python3 hash-12/reproduce_cross_domain.py
```

## hash-12-2: Final-block message bits control a branch, with a measurable timing dependence

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Iphe-512, -768 and -1024; reference, optimized and additional implementations
Discovery: Trivial
Exploitation: Running time depends on the Hamming weight of the final block of a secret message, measured locally; no message recovery demonstrated
Credit: LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool; timing measurement by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17
Original source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/4VZ5ASH4KKC5LNVK6LDPOEJDEAESROUW/)

`load_final_word` assembles each 64-bit word of the final block one bit at a time and branches on each message bit with `if ((local_pos < remaining_bits && get_message_bit(...)) || ...)` (`CryptHash_AlgorithmInstance.c:110-126` in the reference; the optimized and additional sources have the same loop). The final block is always assembled this way, so every message, byte-aligned or not, takes a path that depends on the bits of its last block.

With the message marked as undefined under Valgrind's memcheck, all three trees report the branch. In the reference Iphe-512 at GCC `-O2`, the instruction count of a call on a 256-bit message is exactly a constant plus 3 per message 1-bit. Over 60,000 messages an all-zero message ran about 50 cycles faster than random ones for 256-bit messages and about 180 for 504-bit messages; with Clang `-O2` the running time fell by about 1.5 cycles per message 1-bit (64 standard deviations at 504 bits). The figures vary with the host; they expose the Hamming weight of the final block, not individual bits, and no message was recovered.

Constant-time fix (easy): compute each bit as a masked value and OR it in unconditionally. The repair is local; the rating is Medium because the channel is measured.

### Reproducing

```sh
sh hash-12/reproduce_secret_branch_timing.sh
```

The witness requires the taint result and the exact instruction-count relation, and prints the timing figures as information. It needs Valgrind.
