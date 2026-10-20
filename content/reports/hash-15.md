<!-- synchronized report: hash-15/report.md -->
Candidate: Litchi
Family: Symmetric (permutation-based)
Archive: [Litchi.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Litchi.zip)

## hash-15-1: Litchi-XOF ignores the requested output length and overruns shorter digest buffers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted Litchi-XOF reference `CryptHash` wrapper
Discovery: Trivial
Exploitation: A caller providing a 512- or 768-bit output buffer receives a write beyond it; no secret disclosure or cryptographic break shown
Credit: fa1c4 (University of Science and Technology of China)
Date: 2026-10-20
Original source: [NGCC harness issue 31](https://github.com/ngcc-dev/ngcc-harness/issues/31)

The XOF wrapper accepts `digest_len_bits`, but passes its fixed `DIGEST_BIT_LENGTH = 1024` to `litchi_xof` instead (`Litchi-XOF/CryptHash_AlgorithmInstance.c:14–18` and its header). A caller requesting 512 bits and allocating the corresponding 64 bytes is therefore written 128 bytes. The output-size argument is not checked or honored. The XOF core can take a variable output length; this is a wrapper error, not an attack on the hash construction.

### Reproducing

```sh
make -C hash-15
python3 hash-15/reproduce_xof_output_length.py
```

The native call requests 512 bits in a larger sentinel-backed buffer, confirms that bytes past the requested 64 change, and compares the entire result with a 1024-bit control request. It does not make an out-of-bounds allocation or infer exploitability from the overwrite.
