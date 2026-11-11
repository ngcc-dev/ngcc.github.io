<!-- synchronized report: hash-23/report.md -->
Candidate: QILIN
Family: Symmetric (sponge)
Archive: [QILIN.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/QILIN.zip) (SHA-256: `10335345f6a6cca5e4be688ef42230dff983049483acecbd43f38febb7618609`)

## hash-23-1: Unvalidated digest lengths overrun the final-block stack buffer

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All six reference and optimized `CryptHash` wrappers
Discovery: Trivial
Exploitation: A request for an unsupported digest length writes message bytes past a 265-byte stack buffer, or never returns in the reference; no control-flow hijack demonstrated
Credit: Kr0emer and Chen Peng (陈鹏), Hangzhou Institute of Technology, Xidian University
Date: 2026-11-11
Original source: [GitHub issue #38](https://github.com/ngcc-dev/ngcc-harness/issues/38)

`CryptHash` computes the sponge rate from the caller's `digest_len_bits`, `rate_bits = 3136 - 2*digest_len_bits` (reference `CryptHash_AlgorithmInstance.c:70`, optimized `:17`), and never checks it. The supported lengths of 512, 768 and 1024 bits give rates of at most 264 bytes, which fit the fixed `uint8_t last_block[265]` (`:97`, optimized `:53`). A smaller request gives a larger rate. For 256 bits the rate is 328 bytes, and the final message fragment is copied into `last_block` (`:103`, optimized `:59`). A full fragment gives a 328-byte `memcpy` into the 265-byte stack buffer, a 63-byte overflow of message bytes. The reference then absorbs `rate_words*8` bytes from the same object (`:131–135`), so out-of-bounds stack bytes also enter the returned digest. A request for 1568 bits gives a zero rate, and the reference absorption loop never advances. An unsupported length such as 1000 returns success, with 120 output bytes from the reference and none from the optimized tree.

The overflow is reached by an ordinary-looking request for a shorter digest, with attacker-supplied message bytes as the written data. The wrapper should reject every length other than the supported tiers before computing the rate.

### Reproducing

```sh
sh hash-23/reproduce_digest_length.sh
```

The script checks the unvalidated rate computation in all six wrappers. It then builds each unmodified wrapper with AddressSanitizer. As controls, 512-, 768- and 1024-bit requests with a 2623-bit message must run cleanly. A 256-bit request on the same message must give a `WRITE of size 328` in `CryptHash`. A 1568-bit request to each reference build must still be running after five seconds. It does not attempt to exploit the overwrite.
