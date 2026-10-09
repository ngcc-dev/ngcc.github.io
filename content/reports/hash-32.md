<!-- synchronized report: hash-32/report.md -->
Candidate: ZC-EDMC
Family: Symmetric (sponge)
Archive: [ZC-EDMC.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/ZC-EDMC.zip) (SHA-256: `235157f178c0ec885dad4062ee232cdc0d16e95474f05c6f93038fd951ca3712`)

## hash-32-1: The specified and implemented ZC-EDMC mappings differ

Severity: Low
Status: Confirmed
Layer: Design
Affected: All six ZC-EDMC parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Cryptanalysts001, Institute of Software, Chinese Academy of Sciences <yufei2021@iscas.ac.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/6BKFT5FXW3PL3ZXWNQFTLEIQOJSXZTWK/)

The construction prose and Algorithm 3 define the compression mapping with two different six-round halves, `h(g(X) xor (0^r || X_c))`. A displayed equation instead uses `h(h(X) xor ...)`, and the reference implementation invokes the same last-six-round function twice. It therefore implements the displayed equation rather than Algorithm 3.

The submitted permutation constants introduce a second deterministic mismatch: rounds 5--7 and 9--11 of the code's twelve-round schedule are permuted relative to the specification table. The submitters independently modeled the code schedule and reproduced its KATs, and report that changing the inner call from `h` to `g` changes all 22 tested digests for each of the six instances. This is an interoperability and analysis-target defect, not a demonstrated collision or preimage attack.

### Reproducing

The local checker verifies both calls in every reference instance and the exact submitted constant schedule:

```sh
make -C hash-32 reproduce-forum
```

## hash-32-2: Message modification gives a conditional 2^288 collision estimate

Severity: Critical
Status: Lead
Layer: Design
Affected: ZC-EDMC-1536-768 and -1024; full-round attacks remain conditional
Discovery: Non-trivial
Exploitation: Estimated 2^288 work, conditional on full-round trail independence and reachable starting states
Credit: Qinghe Crypto Group; three-round message-modification extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-29
Original source: [Qinghe Crypto Group's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/4KRD3W3LRMJDQQNL7TYTBCW66P4UUWOY/)

For ZC-1536, the input difference `Delta A_0[0] = 0x1111111111111111` survives the linear layer. At each of its 16 active bit positions, the sequential χ mapping preserves the difference exactly when the two other input bits are `0,1`, a probability of `1/4`; the one-round trail therefore has weight 32. The intermediate capacity feed-forward leaves this rate difference unchanged, and later message-block differences can cancel it and merge the states. The same local trail applies to both mappings present in the archived specification and implementation because it is independent of the round constants and of whether the first six-round half is named `g` or `h`.

The original post's independent-round model gives `2^224`, `2^352`, and `2^384` for 7, 11, and 12 rounds. Further extension: rate-only linear message modification enforces the first three trail rounds. For ZC-EDMC-1536-768, a prefix satisfying 16 capacity conditions and a valid-message collision of the reduced two-plus-two-round hash were demonstrated from the zero IV; a later message block merges the states. For -1024, the systems are soluble on tested chaining states after imposing 32 capacity conditions, but no corresponding prefix was constructed. Assuming independent `2^-32` transitions over rounds 4–12 gives about `2^288` work against the 384- and 512-bit collision targets. The later-round, reachable-state and full-round steps remain open. The conditional cost is below the required collision targets, hence Critical / Lead, not a confirmed full-round collision.

### Reproducing

```sh
python3 security/zc_iterative_differential.py
```

The certificate exhausts the three-bit χ inputs and checks both reported masks against the linear rotations: the 16-active-position mask used above has weight 32 per round, while the all-ones mask used for the reported ZC-1280 reduced-round trail has 64 active positions and weight 128 per round. It then prints the unresolved multi-round limitation.

Run `python3 security/zc_message_modification.py` for the extension's rate-only systems and a replay of the reduced-round collision against the submitted permutation. The witness does not rerun the long search. Its reduced rounds use the reference code's last-round-constant convention, not the first four rounds of the full schedule.
