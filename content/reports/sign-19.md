<!-- synchronized report: sign-19/report.md -->
Candidate: Phoenix
Family: Hash-based signature
Archive: [Phoenix.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Phoenix.zip) (SHA-256: `ec801791976a10baffa852c479afd12362af3b5fb6420104254fb48814d99918`)

## sign-19-1: Phoenix parameter sets define incompatible signature languages

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference/AVX2 pairs SHAKE-128f, SHAKE-128s, SHAKE-192f, and SM3-192s
Discovery: Trivial
Exploitation: Official implementations reject otherwise valid signatures from the same named parameter set
Credit: Qin Zhen
Date: 2026-09-29
Original source: [Qin's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3B6IDLJHSE7TD4NACBIGRT4H3JKRPR7J/)

The specification gives no numeric `SPX_TFORS_SIG_MAX`: Algorithm 19 (physical PDF page 35) requires the transmitted TFORS length to equal the length computed from Octopus pruning. The submitted reference and AVX2 trees instead assign different upper bounds to four identically named parameter sets: respectively 2156/2436, 1716/1732, 5372/5396, and 5274/5298 bytes. The reference verifier enforces its extra upper bound at `sign.c:54`, while the AVX2 signer can emit signatures beyond it. Thus the reference implementation is the non-conforming side of the cross-implementation rejection.

For Phoenix-SHAKE-128f, both submitted implementations reproduce their own ten-record KATs and self-verify. The reference signatures are 13,610–13,658 bytes and the AVX2 signatures 13,722–13,946 bytes; the latter also exceed the specification's advertised 13,668-byte Phoenix-SHAKE-128f size. The AVX2 verifier accepts all ten shorter reference signatures, but the reference verifier rejects all ten AVX2 signatures. A fresh rebuild reproduces record zero exactly: 13,658 versus 13,882 bytes, with the same key and message, and the reference verifier rejects the optimized signature.

This is an implementation-level interoperability defect; no forgery or key recovery is demonstrated, hence Low.

### Reproducing

```sh
python3 sign-19/reproduce_interop.py
```

The script builds both submitted Phoenix-SHAKE-128f implementations in a temporary directory, reproduces the first KAT seed and message, checks both self-verification controls, and prints `CONFIRMED sign-19-1` after the asymmetric cross-verification result.
