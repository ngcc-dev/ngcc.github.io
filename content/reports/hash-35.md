<!-- synchronized report: hash-35/report.md -->
Candidate: Wish
Family: Symmetric (AES-derived sponge hash)
Archive: [Wish.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Wish.zip) (SHA-256: `f878ea89f5b5929c26445a4b1967f21139c74600d5779e4eb5d0bd7f97bea4b5`)

## hash-35-1: Secret-indexed S-box and variable-time field multiplication

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference Wish512 and Wish1024
Discovery: Trivial
Exploitation: Cache or branch side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Every permutation round reads `S_Box[s[i]]` with an evolving secret state byte (`wish.c:98`). Its 256-byte table spans cache lines. `GF_Mul` also loops until a secret-dependent multiplier becomes zero and branches on each multiplier bit (`:86-91`). This gives both memory-address and control-flow leakage; no full preimage recovery is claimed. See [constant_time.md](../constant-time/hash-35.md).

### Reproducing

Inspect `wish.c:86-99` in either reference variant. With multiplier `b=1`, `GF_Mul` executes one iteration; with `b=128`, it executes eight.
