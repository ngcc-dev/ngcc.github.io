<!-- synchronized report: sign-03/report.md -->
Candidate: CEDRUS+C
Family: Hash-based (stateless)
Archive: [cedrus+c.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/cedrus%2Bc.zip) (SHA-256: `a31de849cf0a0703a4e57decbdf4d97b100d00dc74756feaded2c04a7593e110`)

## sign-03-1: Hypertree index collapse causes repeated few-time keys

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all eight parameter sets
Discovery: Trivial
Exploitation: Low-query adaptive signature accumulation
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Every submitted `hash_sm3.c` parses the message digest and then assigns `*tree = 0` instead of decoding the hypertree index. The implementation therefore discards the 64- to 67-bit tree selection required by the specification and repeatedly uses only bottom-layer addresses.

An additional missing-parentheses defect in `SPX_BOTTOM_TREE_HEIGHT` makes the leaf mask retain two fewer bits than intended. The resulting numbers of reachable bottom FORS/WOTS addresses are only 4, 64, 8, 64, 16, 128, 32, and 128 for 160f, 160s, 256f, 256s, 384f, 384s, 512f, and 512s. Thus the initially observed 16-key collapse in 160f is actually a four-address collapse.

A same-key experiment with 100 CEDRUSC-160f signatures produced exactly four bottom authentication paths, with multiplicities 23, 25, 26, and 26. The specification models FORS-instance reuse with a probability near `1/2^h`; the implementation instead repeats few-time FORS and associated WOTS keys after only a handful of signatures.

An end-to-end adaptive attack collected 1,000 signatures on distinct chosen messages, combined disclosed FORS leaves from different signatures, and found a covered digest for a new message after 2,046 `H_MSG` trials. Reusing the selected address's fixed hypertree suffix produced a signature accepted by the submitted verifier. The attack completed in about three CPU-minutes.

This invalidates the submitted concrete-security analysis and enables low-query leaf accumulation and signature reuse attacks. The tree index must be decoded from the digest and every height macro must be parenthesized before use in masks.

### Reproducing

```sh
make -C sign-03 exploit
sign-03/reproduce_forgery sign-03/lib/libCEDRUSC-160f.so
```

## sign-03-2: FORS+C accumulation gives a below-target fresh-message forgery

Severity: High
Status: Confirmed
Layer: Design
Affected: CEDRUS+C-160f and CEDRUS+C-160s specification
Discovery: Moderate
Exploitation: A concrete forgery falls below the target with 2^71–2^76 signatures, but no below-target route is known within the call's 2^64 per-key operational requirement
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-10-04
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KIMAVVYXPRBYTA4VPSKYF6XKVMMLT23J/)

The [pinned analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/6ebb3b4ab00c68d8e72b1c08ba839ed7056dc166/CEDRUS%2BC) validates the following result.

Ordinary independently randomized signatures that reach one complete bottom address disclose different FORS+C leaves and authentication paths under the same address-specific public key (Algorithms 17–18, physical pp. 35–36; §3.2, p. 45). An attacker can combine covered coordinates and retain one valid hypertree suffix. For a fresh message it then enumerates the public serialized `R` and counter fields until `H_msg` selects the accumulated address and covered coordinates; verification has no secret test for how those public values were generated.

For the two 128-bit-target sets, constant-success strategies use about `2^71.220` signing queries plus `2^66.934` target trials for 160f, or `2^75.587` plus `2^71.982` for 160s. This is the few-time degradation already parameterized by `q_sig` in §3.2, combined into a concrete forgery. At exactly `2^64` signatures, however, the one-target success probabilities are only about `2^-160.09` and `2^-160.49`; roughly `2^159.6` and `2^160.0` public target trials are needed for 50% success. We found no specification-only route below `2^128` within the call's `2^64` per-key operational requirement. The broader attack remains inside the separate `2^80` evaluation ceiling, so it is retained as High while that mismatch remains unresolved.

The full attack is certificational rather than physically practical. For 160f the fully provisioned table is about `2^79.27` bytes and returned signatures about `2^88.49` bits; for 160s they are about `2^79.73` bytes and `2^91.80` bits. A scaled strict-verifier forgery and native full-parameter coordinate-splicing checks pass.

### Reproducing

```sh
sh sign-03/reproduce_fors_accumulation.sh
```
