<!-- synchronized report: hash-25/report.md -->
Candidate: TaiChi
Family: Symmetric (sponge-like hash)
Archive: [TaiChi.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/TaiChi.zip) (SHA-256: `013bdcd9c7fdcce5bfbfaae84f02f20c5c4ae8a88cb742e7da3fddafeef2e7de`)

## hash-25-1: Allocation failure reports success without writing a digest

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference TaiChi-512/768/1024
Discovery: Moderate
Exploitation: Resource-contingent false-success output; not a normal-operation cryptanalytic collision
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

`TaiChi_Hash` returns without writing its output if allocation of the padded-message buffer fails. Its public `CryptHash` wrapper nevertheless returns success. With a 0xa5-initialized output buffer and a bounded address space, two distinct 16-MiB inputs both returned `0` while leaving all 64 output bytes unchanged. A changed-message control hashes to distinct values with available memory, and the ordinary TaiChi-512 KAT passes.

This is a fail-open API defect, not a collision in the successfully executed TaiChi construction. The digest is entirely whatever data the caller left in the output buffer; depending on that data, the failure can masquerade as a valid digest. The hash routine must return an allocation error and the wrapper must propagate it.

### Reproducing

```sh
make -C hash-25 exploit
```

The Linux witness preallocates the input, caps process virtual memory at its current use plus 4 MiB, and checks that two calls leave the same sentinel buffer unchanged while reporting success.

## hash-25-2: The reference TaiChi-1024 leaks its padded message buffer on every call

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: TaiChi-1024 reference implementation; TaiChi-512, TaiChi-768 and the optimized implementation are not affected
Discovery: Trivial
Exploitation: Unbounded memory growth in a long-running process that hashes repeatedly; no disclosure or corruption
Credit: LK-PQC-Hunter (NGCC CryptHash Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-17
Original source: [LK-PQC-Hunter's CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/MXN3J7WZ5SVY7QY5YU2BOABMREACB6L2/)

`TaiChi_Hash` allocates the padded message with `buf = malloc(padded_len)` (`CryptHash_AlgorithmInstance.c:246`). The 512- and 768-bit references free it after copying the digest (`:272`). The 1024-bit reference squeezes twice and returns without freeing it, so every call leaks one block the size of the padded message. With `malloc` and `free` wrapped, 100 calls left 100 live blocks for TaiChi-1024 and none for TaiChi-512 or TaiChi-768.

Fix: free the buffer before returning.

### Reproducing

```sh
sh hash-25/reproduce_leak.sh
```
