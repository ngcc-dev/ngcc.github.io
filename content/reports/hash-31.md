<!-- synchronized report: hash-31/report.md -->
Candidate: The ZC-DMC Hash Function
Family: Symmetric (feed-forward sponge)
Archive: [ZC-DMC.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/ZC-DMC.zip) (SHA-256: `b6da323d388d3411b882228152f25626999502b8c246cc0c9b64a0a9d72eaaac`)

## hash-31-1: Cross-domain distinguisher between ZC-1536-512 and ZC-1536-768

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified ZC-DMC-1536-512 and ZC-DMC-1536-768 construction
Discovery: Moderate
Exploitation: Moderate
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/CVL24T5A4ILSD6V2GACF73MENNFQC3JB/)

The two instances share the same 1536-bit permutation and zero initial state, while moving the rate/capacity feed-forward boundary. Further extension to Tsinghua Hash Lab's analysis: take a common first 704-bit block (zero-extended to 960 bits for the 512 profile), then a zero block. After these two absorptions the states differ only at bits 704–959, by `D = P(B1)[704:960]`. Putting `D` in that region of the 512 profile's third block makes both final permutation inputs equal. Feed-forward leaves their first 704 state bits equal, so the first 64-bit squeeze blocks agree. The first-block counter value 13 gives the four-bit suffix needed to make both final blocks valid under the mandatory `M || 01 || 10*1` padding.

The official 512- and 768-bit `CryptHash` libraries return the same first eight digest bytes, `7a07b396b47dfec4`, for the constructed messages. A one-bit control differs. This is a cross-profile distinguisher (ideal probability `2^-64`), **not** a same-instance or full-digest collision.

Follow-up analysis: the [Iphe Algorithm Group's cross-rate note, posted by 崔灏睿 on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BWXG6OPAIQL32FMWWYJ3C4D6QMRGHGP4/) gives an independent three-block ZC-DMC witness. The [ZC-DMC team's response on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/R4Y2U6SYSDUPFSVPGYIYSXGWVGQKVIDJ/) acknowledges the relation; this report concerns the archived zero-IV submission.

### Proposed fixes

The [ZC-DMC team's response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/R4Y2U6SYSDUPFSVPGYIYSXGWVGQKVIDJ/) proposes distinct three-bit IV tags for the profiles. This section records the proposal without evaluating it.

### Reproducing

From the repository root, run `make -C hash-31 exploit`. The witness uses only the two official archived hash libraries for its verdict and prints `CONFIRMED hash-31-1`.

## hash-31-2: Message modification gives a conditional 2^288 collision estimate

Severity: Critical
Status: Lead
Layer: Design
Affected: ZC-DMC-1536-768 and -1024; full-round attacks remain conditional
Discovery: Non-trivial
Exploitation: Estimated 2^288 work, conditional on full-round trail independence and reachable starting states
Credit: Qinghe Crypto Group; three-round message-modification extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-29
Original source: [Qinghe Crypto Group's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/UPLLMJ35VZ5K7U2BZ7RHJMVYG2ZSRN2Z/)

For ZC-1536, the input difference `Delta A_0[0] = 0x1111111111111111` survives the linear layer. At each of its 16 active bit positions, the sequential χ mapping preserves the difference exactly when the two other input bits are `0,1`, a probability of `1/4`; the one-round trail therefore has weight 32. Capacity-only feed-forward leaves this rate difference unchanged, after which a message-block difference can cancel it and merge the states.

The original post's independent-round model gives `2^224`, `2^352`, and `2^384` for 7, 11, and 12 rounds. Further extension: rate-only linear message modification enforces the first three rounds. For ZC-DMC-1536-768, a prefix satisfying 16 capacity conditions and a valid-message collision of the four-round reduced hash were demonstrated from the zero IV; the next block cancels the remaining rate difference. For -1024, the analogous systems are soluble on tested chaining states with 32 capacity conditions imposed, but a prefix reaching one was not constructed. Assuming independent `2^-32` transitions over rounds 4–12 gives about `2^288` work against 384- and 512-bit collision targets. The independence, reachable-state and full-round steps remain open. The conditional cost is below the required collision targets, hence Critical / Lead, not a confirmed full-round collision.

### Reproducing

```sh
python3 security/zc_iterative_differential.py
```

The certificate exhausts the three-bit χ inputs and checks both reported masks against the linear rotations: the 16-active-position mask used above has weight 32 per round, while the all-ones mask used for the reported ZC-1280 reduced-round trail has 64 active positions and weight 128 per round. It then prints the unresolved multi-round limitation.

Run `python3 security/zc_message_modification.py` for the extension's rate-only systems and a replay of the reduced-round collision against the submitted permutation. The witness does not rerun the long search. Its reduced permutation uses the reference code's last-four-round constants, not the first four rounds of the full schedule.

## hash-31-3: An 8-column iterative trail gives an estimated 2^125 collision

Severity: Critical
Status: Lead
Layer: Design
Affected: ZC-DMC-1536-512 and -768
Discovery: Non-trivial
Exploitation: Estimated 2^125.1 (-512) and 2^129 (-768) work, conditional on independence over ten probabilistic rounds; collisions executed for three and four rounds only
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-31

Fix a bit position `z` and let `D` have plane 0 active on the odd lanes and plane 2 active on the even lanes, all at `z`. The plane-2 ρ offset `(5, 0)` has no z-rotation, so after the first ρ the active bits share columns, θ sees zero column parity, and the second ρ maps the even lanes back onto themselves: the linear layer fixes `D` exactly. Each active χ column keeps its difference with probability 1/4; consecutive rounds are correlated, and the measured rate is 2^-12 per round from every start round.

In the first block, a rate difference on plane 0 at `z` becomes `W` (planes 0 and 2, all lanes) and then `D`. After a prefix fixes 9 (-512) or 13 (-768) capacity bits, message modification makes the first two rounds free, so the block costs about 2^120. The second block cancels the rate part of `D` and follows `D → D` for all twelve rounds; its output difference is rate-only, and a third message block cancels it. Its own 5 or 9 capacity conditions repeat the first block 2^5 or 2^9 times, giving about 2^125.1 and 2^129 against collision targets of 2^256 and 2^384.

The 2^-12 rate was measured for single rounds at every start and for windows of up to four rounds; independence across ten consecutive probabilistic rounds is assumed. No full-round collision was attempted.

### Reproducing

```sh
sh security/zc_column_trail.sh
```

The script checks that the reference linear layer fixes the trail patterns at every `z` and measures the one-round rate at each start round. It then finds fresh three-round collisions for ZC-DM and ZC-DMC at -512 and -768 from the zero IV with padding, replays stored four-round -512 collisions, and checks every pair with the independent Python mode model. The full twelve-round digests differ. It uses the reference code's last-R-round convention and runs in about 10 seconds.
