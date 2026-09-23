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

The [Iphe Algorithm Group subsequently revised the profiles](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/3NHT6MB6FTPF63JO7YXX3Y6HH422SQGC/) to use distinct IVs; this report applies to the archived, SHA-256-pinned submission, not the revised one.

Follow-up analysis: the [group's cross-rate note, posted by 崔灏睿 on 2026-09-23](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/BWXG6OPAIQL32FMWWYJ3C4D6QMRGHGP4/), gives the general feed-forward construction and an independent full-round Iphe witness. Its distinct-IV caveat agrees with the revised-profile scope above.

### Reproducing

```sh
make -C hash-12 lib/libIphe-512.so lib/libIphe-1024.so
python3 hash-12/reproduce_cross_domain.py
```
