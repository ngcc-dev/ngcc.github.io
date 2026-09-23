<!-- synchronized report: hash-22/report.md -->
Candidate: Pavelor
Family: Symmetric (AES-derived sponge hash)
Archive: [Pavelor.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Pavelor.zip) (SHA-256: `0414e5f0039c2d352eb00c125554114931363dcea6b382052fdd20fbf25e0c31`)

## hash-22-1: Secret state indexes AES S-box; tail bits branch

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference Pavelor-512/768/1024
Discovery: Trivial
Exploitation: Cache or branch side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The round function reads `AES_SBOX[in[i]]` for each secret-dependent state byte (`CryptHash_AlgorithmInstance.c:77`). The 256-byte table spans cache lines. Additionally, `xor_bit` branches on each message bit in the final partial block (`:177,199-200`); GCC `-O2` retains a conditional jump. No complete message-recovery experiment was run. See [constant_time.md](../constant-time/hash-22.md).

### Reproducing

Inspect the cited S-box access and compile the reference file with `gcc -O2 -g -c`; `objdump -dSl` shows `bt`/`jae` at `xor_bit`.
