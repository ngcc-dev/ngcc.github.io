<!-- synchronized report: hash-14/report.md -->
Candidate: Laurus
Family: Symmetric (permutation-based)
Archive: [Laurus.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Laurus.zip) (SHA-256: `9499a772e532577f85902c0f631a95af8e2fb4bc308da6466c076debd63d1415`)

## hash-14-1: Laurus loses its function-domain separation at c=1024 and c=512

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified generic `Laurus[c,fid]` interface at `c=1024`; named Laurus-512 and Laurus-XOF (`c=512`) for 1537-2560-bit messages; reference implementations
Discovery: Moderate
Exploitation: Trivial
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn> (generic interface); named-function extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/YGSFWSHQSIOIFIJTX6IBSDQCV25WS7I2/)
Follow-up source: [Laurus team's 2026-09-24 response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/CC2SBG5TUNBN5ZD2WWEKITUQEVNJD56L/)

The specification uses `fid=0` for hashing and `fid=1` for XOF operation, placing the identifier only in the initial state. At `c=1024`, a message of 513 to 1024 bits causes one 512-bit absorption. That absorption omits the identifier from the permutation input and moves its difference into the first eight state words; finalization then discards exactly those words. The complete output is consequently independent of `fid`.

For example, the 768-bit all-zero message has identical 1024-bit outputs under `Laurus[1024,0]` and `Laurus[1024,1]`. This is a functional-domain separation failure, not a collision between distinct messages.

Extended on 2026-10-17: the same loss reaches the named functions. Laurus-512 is `Laurus[512,0]` and Laurus-XOF is `Laurus[512,1]` (§2.4-2.5, physical PDF page 11). The identifier sits only in the last state word (`S_0 = [2^63 fid + c]`, §2.2, page 7; `laurus_512.c:163`). At `c=512`, `g0` passes state words 8-23 to the feed-forward half without permuting them (`:108-124`). Each absorption therefore moves the identifier difference down eight words, from `S_0[23]` to `S_1[15]` to `S_2[7]`, and `g1` never reads `S[7]` (`:127-141`). Every message of 1537 to 2560 bits takes exactly two absorptions before finalization, so `Laurus-512(M) = MSB_512(Laurus-XOF(M))` for every such `M`. For example, the 2048-bit all-zero message gives `309e429e…aad67432` under Laurus-512 and as the first 512 bits of Laurus-XOF. Shorter and longer messages remain separated. Through the uniform API, the two named functions are therefore related outputs rather than independent functions on this length window.

The [Laurus team confirmed the generic-interface defect](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/CC2SBG5TUNBN5ZD2WWEKITUQEVNJD56L/) while reiterating that the named XOF uses `c=512`. As shown above, `c=512` does not avoid the loss for 1537-2560-bit messages. The archived specification remains the target here.

### Proposed fixes

The [Laurus team's response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/CC2SBG5TUNBN5ZD2WWEKITUQEVNJD56L/) proposes repeating the function-ID-bearing initialization value across all three 512-bit state segments. This section records the proposal without evaluating it.

### Reproducing

The target exposes the otherwise internal generic interface from the submitted source, checks the 768-bit equality, and checks a 512-bit negative control:

```sh
make -C hash-14 reproduce
```

The named-function extension uses the submitted Laurus-512 and Laurus-XOF libraries:

```sh
python3 hash-14/reproduce_named_xof_prefix.py
```

It tests every length from 0 to 3199 bits on three random streams and the all-zero stream. It requires equality for exactly the 1537-2560-bit lengths and none outside that window, and it checks the two named wrappers in the source (`laurus_512.c:260`, `laurus_xof.c:261`). It runs in under one second.

## hash-14-2: Laurus-XOF ignores the requested output length and overruns shorter digest buffers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted Laurus-XOF reference `CryptHash` wrapper
Discovery: Trivial
Exploitation: A caller providing a 512- or 1024-bit output buffer receives a write beyond it; no secret disclosure or cryptographic break shown
Credit: fa1c4 (University of Science and Technology of China)
Date: 2026-10-20
Original source: [NGCC harness issue 30](https://github.com/ngcc-dev/ngcc-harness/issues/30)

The XOF wrapper accepts `digest_len_bits`, but passes its fixed `DIGEST_BIT_LENGTH = 2048` to `laurus_xof` instead (`Laurus-XOF/CryptHash_AlgorithmInstance.c:14–18` and its header). A caller requesting 512 bits and allocating the corresponding 64 bytes is therefore written 256 bytes. The output-size argument is not checked or honored. The XOF core can take a variable output length; this is a wrapper error, not an attack on the hash construction.

### Reproducing

```sh
make -C hash-14 lib/libLaurus-XOF.so
python3 hash-14/reproduce_xof_output_length.py
```

The native call requests 512 bits in a larger sentinel-backed buffer, confirms that bytes past the requested 64 change, and compares the entire result with a 2048-bit control request. It does not make an out-of-bounds allocation or infer exploitability from the overwrite.
