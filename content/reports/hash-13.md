<!-- synchronized report: hash-13/report.md -->
Candidate: JuziHash
Family: Symmetric (sponge and capacity feed-forward)
Archive: [Juzi.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Juzi.zip) (SHA-256: `487f73e34dac7a06ae6718c4a38bcf757c1555676b107415f7b79b17d8c9cf92`)

## hash-13-1: Long messages reduce JuziHash-1024 second-preimage security below 1024 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: JuziHash-1024 specification and implementations
Discovery: Trivial
Exploitation: About 2^970 work for a target of 2^54 blocks; no second preimage has been computed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-27

The [NGCC hash call](https://www.niccs.org.cn/niccs/Notice/pc/content/content_1975892908773478400.html) requires second-preimage security of at least h bits for an h-bit digest ([Evaluation Criteria](https://www.niccs.org.cn/niccs/Notice/crlRB1ZY.pdf) §1(2)) and message lengths of at least 2^64 − 1 bits, which JuziHash-1024 does not meet for long messages.

JuziHash-1024 injects each 1024-bit block into the rate and feeds the previous 1024-bit capacity forward after the permutation; the digest is the capacity (§5.2; `CryptHash_AlgorithmInstance.c:227-289`). A long target offers many intermediate states. An expandable message can be built from collisions in the 1024-bit capacity projection. If two branch states have equal capacity, one corrective message block cancels their rate difference before the permutation, after which the complete states merge. These components cost about k·2^513; linking to one of 2^k target capacities costs about 2^(1024−k). The specification concedes the resulting long-message effect: a target of 2^k blocks reduces second-preimage cost by about k bits, and valid inputs of up to 2^54 blocks give "a worst-case long-message scale around 2^970 for JuziHash-1024" (§5.5, physical PDF pages 19–20). Its Table 2 nevertheless lists 2^1024 (page 24), to be read only for "ordinary-message or fixed-length" inputs.

### Reproducing

Compare the call requirement with §5.5 (physical PDF pages 19–20) and Table 2 (page 24) of the specification.
