<!-- synchronized report: hash-11/report.md -->
Candidate: Garnet
Family: Symmetric (AES-derived hash)
Archive: [Garnet.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Garnet.zip) (SHA-256: `9cb659f7e01a64bdcce2a4fea8a7d6e6b5687b2a0ed8ce4ffe5fa86dd3e77646`)

## hash-11-1: Secret state indexes AES T-tables

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference Garnet variants
Discovery: Trivial
Exploitation: Cache side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Each AES-like round indexes four 1-KiB T-tables with bytes of the evolving hash state (`Garnet_1024.c:278-281`; `Garnet_512.c:322-325`). These indices depend on the message and select different cache lines, exposing state-dependent memory addresses in a shared-cache setting. A two-entry reduction table is also indexed by a state bit. No preimage-recovery exploit is claimed. See [constant_time.md](../constant-time/hash-11.md).

Constant-time fix (easy, hence Low): the round is an AES round, so use the AES instruction (`aesenc`, or ARMv8 `aese`/`aesmc`) as the specification intends, and a `pshufb` vector-permute or bitsliced AES where it is unavailable. The two-entry reduction table becomes a mask.

### Reproducing

Inspect the cited `TE0`–`TE3` loads; identical-length inputs with different first blocks produce different state-derived table indices. This is an address-trace witness, not a timing-extraction benchmark.

## hash-11-2: Garnet-1024a omits the specified rate-state feed-forward

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference `Garnet_1024.c` (Garnet-1024a); the optimized assembly was not checked
Discovery: Moderate
Exploitation: The stated Sponge-DM bound does not cover the submitted reference function; no collision or preimage attack is demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-09

The specification defines each Sponge-DM absorption as `X = S xor I_r(M)` and `S' = P^12(X) xor X` (§2.5 and Proposition 2, physical pp. 9–10). Proposition 2 explicitly relies on this *full-state* feed-forward. The reference code instead saves only the old capacity, absorbs the message, permutes, then XORs the message and saved capacity (`Garnet_1024.c:665–682, 820–829, 868–873`). Its update is `S' = P^12(X) xor I_r(M) xor (0_r || S_c)`, omitting the old rate state `S_r`. The formulas differ by `I_r(S_r)`.

The native witness checks the difference against the submitted reference functions, including a zero-rate-state control where the formulas agree. A separate local model/KAT check, not part of this reproducer, found that the code's empty-message digest matches its KAT while the specified feed-forward gives a different digest. This is a conformance and proof-applicability gap, not evidence that the implemented hash misses a collision or preimage target.

### Reproducing

```sh
python3 hash-11/reproduce_dm_feedforward.py
```
