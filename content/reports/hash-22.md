<!-- synchronized report: hash-22/report.md -->
Candidate: Pavelor
Family: Symmetric (AES-derived sponge hash)
Archive: [Pavelor.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Pavelor.zip) (SHA-256: `0414e5f0039c2d352eb00c125554114931363dcea6b382052fdd20fbf25e0c31`)

## hash-22-1: Secret state indexes the AES S-box and message bits control a branch, with a measurable timing dependence

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference Pavelor-512/768/1024; the optimized implementation uses AES instructions and is not affected
Discovery: Trivial
Exploitation: Running time depends on the Hamming weight of the final partial block of a secret message, measured locally; the table lookups add a cache channel that was not measured; no message recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The round function reads `AES_SBOX[in[i]]` for each secret-dependent state byte (`CryptHash_AlgorithmInstance.c:77`). The 256-byte table spans cache lines. Separately, the final partial block is absorbed bit by bit, and `xor_bit` branches on each message bit (`:177,199-200`); GCC `-O2` retains the conditional jump. This applies to every message whose length is not a multiple of the rate, byte-aligned or not.

The branch is measurable in the reference Pavelor-512. For 504-bit messages the instruction count of a call is exactly a constant plus 7 per message 1-bit. Over 60,000 messages the running time rose by about 0.7 cycles per message 1-bit (9 standard deviations), and an all-zero message ran 216 cycles faster than random ones. The optimized build is clean under the same test. The figures vary with the host; they expose the Hamming weight of the final partial block, not individual bits, and no message was recovered. See [constant_time.md](../constant-time/hash-22.md).

Constant-time fix (easy): the specification defines the round as `AESENC`, so use the AES instruction, with a `pshufb` or bitsliced AES fallback; the tail-bit branch becomes a masked XOR. The repair is local; the rating is Medium because the channel is measured.

### Reproducing

```sh
sh hash-22/reproduce_secret_branch_timing.sh
```

The witness requires the taint result and the exact instruction-count relation, and prints the timing figures as information. It needs Valgrind.
