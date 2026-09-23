<!-- synchronized report: hash-05/report.md -->
Candidate: uHash
Family: Symmetric (block-cipher-based hash)
Archive: [uHash.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/uHash.zip)

## hash-05-1: Secret state indexes a 256-byte substitution table

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference uHash-512/768/1024
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The reference `RoundFunction` xors the evolving state with a round key, then reads `S[X[i]]` and `S[Y[i]]` (`CryptHash_AlgorithmInstance.c:163-174`). `S` contains 256 bytes (`:36`), spanning cache lines. Equal-length messages can therefore select different lookup addresses during hashing. No complete message-recovery experiment is claimed. See [constant_time.md](../constant-time/hash-05.md).

### Reproducing

Inspect the cited table accesses in any reference variant. The lookup indices are the evolving `P[i] ^ RK[i]` bytes, not public counters.
