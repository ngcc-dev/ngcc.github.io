<!-- synchronized report: hash-30/report.md -->
Candidate: ZC-DM
Family: Symmetric (feed-forward sponge)
Archive: [ZC-DM.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/ZC-DM.zip) (SHA-256: `47e6297d4d707897c64a75a0b490152b2c67abfb1777d89d225b4bcf58a0063b`)

## hash-30-1: Message modification gives a conditional 2^288 collision estimate

Severity: Critical
Status: Lead
Layer: Design
Affected: ZC-DM-1536-768 and -1024; full-round attacks remain conditional
Discovery: Non-trivial
Exploitation: Estimated 2^288 work, conditional on full-round trail independence and reachable starting states
Credit: Qinghe Crypto Group; three-round message-modification extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-29
Original source: [Qinghe Crypto Group's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/FCGYUVDJV4QBMGG64KAK6X2QZOZ6W4QX/)

For ZC-1536, the input difference `Delta A_0[0] = 0x1111111111111111` survives the linear layer. At each of its 16 active bit positions, the sequential χ mapping preserves the difference exactly when the two other input bits are `0,1`, a probability of `1/4`; the one-round trail therefore has weight 32. If it persists for `t` rounds, Davies–Meyer feed-forward cancels the identical input/output difference and produces a collision at estimated cost `2^(32t)`.

The original post estimates `2^224`, `2^352`, and `2^384` for 7, 11, and all 12 rounds. Further extension to that analysis: rate-only linear message modification can enforce the first three trail rounds. For ZC-DM-1536-768, a prefix satisfying 16 capacity conditions and a collision of the resulting four-round reduced hash were demonstrated using valid padded messages from the zero IV. For -1024, the linear systems are soluble on tested chaining states after imposing 32 capacity conditions, but no prefix reaching such a state was constructed. If each of rounds 4–12 then costs an independent `2^32`, both sets have an estimated `2^288` collision route, below their 384- and 512-bit collision targets. Independence and full-round satisfiability are unproved. The conditional cost is below the required collision targets, hence Critical / Lead, not a confirmed full-round collision.

### Reproducing

```sh
python3 security/zc_iterative_differential.py
```

The certificate exhausts the three-bit χ inputs and checks both reported masks against the linear rotations: the 16-active-position mask used above has weight 32 per round, while the all-ones mask used for the reported ZC-1280 reduced-round trail has 64 active positions and weight 128 per round. It then prints the unresolved multi-round limitation.

Run `python3 security/zc_message_modification.py` for the extension's rate-only systems and a replay of the reduced-round collision against the submitted permutation. The witness does not rerun the long search. Its four-round function uses the reference code's last-four-round convention, not the first four rounds of the full schedule.

## hash-30-2: An 8-column iterative trail gives an estimated 2^125 collision

Severity: Critical
Status: Lead
Layer: Design
Affected: ZC-DM-1536-512 and -768
Discovery: Non-trivial
Exploitation: Estimated 2^125.1 (-512) and 2^129 (-768) work, conditional on independence over ten probabilistic rounds; collisions executed for three and four rounds only
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-31

Fix a bit position `z` and let `D` have plane 0 active on the odd lanes and plane 2 active on the even lanes, all at `z`. The plane-2 ρ offset `(5, 0)` has no z-rotation, so after the first ρ the active bits share columns, θ sees zero column parity, and the second ρ maps the even lanes back onto themselves: the linear layer fixes `D` exactly. Each active χ column keeps its difference with probability 1/4; consecutive rounds are correlated, and the measured rate is 2^-12 per round from every start round.

In the first block, a rate difference on plane 0 at `z` becomes `W` (planes 0 and 2, all lanes) and then `D`. After a prefix fixes 9 (-512) or 13 (-768) capacity bits, message modification makes the first two rounds free, so the block costs about 2^120. The second block cancels the rate part of `D` and follows `D → D` for all twelve rounds; the Davies–Meyer feed-forward then cancels the identical input and output difference. Its own 5 or 9 capacity conditions repeat the first block 2^5 or 2^9 times, giving about 2^125.1 and 2^129 against collision targets of 2^256 and 2^384.

The 2^-12 rate was measured for single rounds at every start and for windows of up to four rounds; independence across ten consecutive probabilistic rounds is assumed. No full-round collision was attempted.

### Reproducing

```sh
sh security/zc_column_trail.sh
```

The script checks that the reference linear layer fixes the trail patterns at every `z` and measures the one-round rate at each start round. It then finds fresh three-round collisions for ZC-DM and ZC-DMC at -512 and -768 from the zero IV with padding, replays stored four-round -512 collisions, and checks every pair with the independent Python mode model. The full twelve-round digests differ. It uses the reference code's last-R-round convention and runs in about 10 seconds.
