<!-- synchronized report: kex-03/report.md -->
Candidate: CreTAKE
Family: Lattice (composite AKE: KEM + signature)
Archive: [CreTAKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CreTAKE.zip) (SHA-256: `0b356074741bc20fa82132719e1678e001083b9746f5c4c582425b727b511741`)

## kex-03-1: Bits-versus-bytes error reduces the ephemeral secret to 64 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, 23 source files including all six S2S instances
Discovery: Trivial
Exploitation: 2^64 offline
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The responder requests 64 bytes (512 bits) of fresh randomness:

`get_random_number(&drng_algorithm, buf, SEED_BYTES * 8ULL)`

It then expands that value with:

`pseudoXOF((MSG_LEN_BYTES + SEED_BYTES) * 8, buf, SEED_BYTES, buf2)`

The third `pseudoXOF` argument is a bit count, but `SEED_BYTES` is 64. Only the first eight bytes of the 64-byte buffer are absorbed. The correct `SEED_BYTES * 8` form appears commented out immediately above related call sites. The erroneous pattern occurs in 23 reference source files and is preserved by every submitted test vector.

In the six S2S instances, this 64-bit value is the only secret input to the session-key computation. A passive eavesdropper enumerates the `2^64` possible inputs, regenerates the deterministic encryption coins and candidate plaintext, and matches the observed ciphertext. This recovers the session key offline at every claimed 128-, 256-, and 512-bit level.

### Reproducing

This is a source and key-space review; a `2^64` search is not run. Fetch the
official archive and inspect the responder call in, for example,
`CreTAKE128/CreTAKE-S2S-BiT128-eZEN128/KEX_AlgorithmInstance.c` line 156. The
second `pseudoXOF` length argument is 64 **bits**, not the intended 64 bytes.

```sh
IDS=kex-03 ./download.sh
./extract.sh kex-03
rg -n -F 'buf, SEED_BYTES, buf2' kex-03/Implementations/Reference_Implementation
```

The same defect reduces the claimed weak forward secrecy of K2S and S2K instances to `2^64` after compromise of the complementary long-term KEM key. This is an implementation error, not a cryptanalytic attack on the specified primitives.

A related initiator-side call passes `SEED_BYTES * 8` as the requested output length but only `SEED_BYTES + SKI_LEN` as the `pseudohash` input bit count. In those instances `SKI_LEN/8 > 56`, so all 64 random bytes are still absorbed and this second units error does not reduce entropy further. It confirms that the bits-versus-bytes confusion is systematic.
