<!-- synchronized report: kem-14/report.md -->
Candidate: DTRU
Family: Lattice-based (NTRU)
Archive: [DTRU.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DTRU.zip) (SHA-256: `ed443d6a9e2e6c50e4956e9b30ce078ae0598a8846962d04b9894cac0816527b`)

## kem-14-1: Caller-declared ciphertext length overflows a decapsulation stack buffer

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All seven reference parameter-set source trees; runtime-confirmed in DTRU-Light and DTRU-1024
Discovery: Trivial
Exploitation: In-process memory corruption and process termination; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The official `kem_dec` API accepts a caller-supplied `ct_len_bytes`, but the reference implementation does not verify it against the instance's fixed ciphertext length. It copies that many bytes into a stack buffer sized for the fixed ciphertext plus `Z` and a short prefix, then writes `Z` at offset `ct_len_bytes`. A correctly allocated, longer input therefore causes an out-of-bounds stack write inside decapsulation. The same unchecked loops appear in all seven reference source trees.

For DTRU-Light, a valid 512-byte ciphertext decapsulates to the honest shared secret; passing those same bytes followed by 48 allocated zero bytes with declared length 560 aborts with stack-smash detection. DTRU-1024 behaves likewise at lengths 1280 and 1360. The effect is memory corruption and availability loss, not a demonstrated confidentiality break. An application that enforces the exact ciphertext length before calling the library can avoid this path, but the submitted API does not enforce that requirement itself.

### Reproducing

```sh
make -C kem-14 exploit
```

The witness tests two independent instances, gives the library an input allocation matching the declared length, checks normal decapsulation first, and isolates each crash in a subprocess. It prints `ATTACK kem-14-1 ... CONFIRMED` for both.
