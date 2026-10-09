<!-- synchronized report: hash-03/report.md -->
Candidate: C Hash
Family: Symmetric (Rocket-JH / C-Engine)
Archive: [C Hash.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/C%20Hash.zip) (SHA-256: `d6b40f34b4c4af7ab1929816d8613220ed669aace6bfdd8d2e9496d90ddc5438`)

## hash-03-1: A backward tree reduces C-Hash-1024 second-preimage work below 1024 bits

Severity: Critical
Status: Probable
Layer: Design
Affected: C-Hash-1024 VIL/FIL mode for messages of at least 2,944 bits; C-Hash-512 and the short-message LDRH path are outside this finding
Discovery: Non-trivial
Exploitation: About 2^983 C-Engine calls and 2^491 stored states in the two-level model; no full-size second preimage computed
Credit: Bishwajit Chakraborty, with AI assistance; padding-aware extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-09
Original source: [CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/VWOZYVZ5J67G7EDHBFZG4JIEWBLRS3WP/) and [attack package](https://github.com/bishwajitchakrabort/ngcc/tree/main/chash1024-second-preimage)

The submitted [specification](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101540728942972928.html) claims 2^1024 second-preimage work for C-Hash-1024 (Table 6, physical p. 22; Appendix C.7.2, pp. 58–59). Its CTR-Func VIL round has a 1,472-bit state and a 736-bit message block. Writing `G_i(x) = LMB_1472(C-Engine(x || ctr_i)) XOR x`, the update is `h_i = G_i(x_i) XOR (0 || m_i)`, where `x_i = h_(i-1) XOR (m_i || 0)`. Given a target state, each forward probe for `x_i` therefore yields a predecessor when the left 736 bits of `G_i(x_i)` match the target; its right half determines `m_i`. This is a forward-only test and is not stopped by CTR-Func's feed-forward. The submitted reference code performs precisely these operations (`CryptHash_AlgorithmInstance.c:288–309,551–575` in `CHash_1024`).

With `N` probes at each of two distinct counters, the expected predecessor-tree sizes are `N/2^736` and `N²/2^1472`. Stream `F` reachable prefix states against the second level; a full-state match is expected when `F N²/2^2944` is about one. Taking `F = N ≈ 2^981.33` gives roughly `2^983.33` permutation calls, including the two-block forward prefixes, and about `2^490.67` stored predecessor states. This is a modeled cost, not a completed search; it assumes the full C-Engine outputs and reachable states behave sufficiently like independent random samples.

The reporter's toy chooses every final VIL block freely, but real C-Hash pads the final block. Our extension keeps the challenge's final padded block unchanged and targets the state immediately before it. For any message of at least four full 736-bit blocks (368 bytes), two earlier full blocks supply the forward prefixes and two full blocks form the backward tail. The forged message has the same bit length and padding, reaches the same state before the copied final block, and hence has the same digest. This preserves the cost above. No shorter-message or first-preimage break is claimed.

### Reproducing

```sh
python3 hash-03/reproduce_backward_tree.py
```

The offline witness checks the frozen reference source's mode structure, then finds a distinct padded same-length second preimage in a 20-bit-state toy CTR-Func construction with separate round counters. It includes changed-message and changed-padding controls. The toy substitutes a Feistel permutation for C-Engine; it does not execute the exponential full-parameter search.
