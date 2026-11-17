<!-- synchronized report: hash-15/report.md -->
Candidate: Litchi
Family: Symmetric (permutation-based)
Archive: [Litchi.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Litchi.zip) (SHA-256: `16c798c93c6fbdc9ac3703113c120fe22df46569a93d7322aaba46effa3273eb`)

## hash-15-1: Litchi wrappers ignore the requested output length and overrun shorter digest buffers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted Litchi-XOF and fixed-output Litchi-512, -768 and -1024 reference `CryptHash` wrappers
Discovery: Trivial
Exploitation: A caller providing a 512- or 768-bit output buffer receives a write beyond it; no secret disclosure or cryptographic break shown
Credit: fa1c4 (University of Science and Technology of China)
Date: 2026-10-20
Original source: [NGCC harness issue 31](https://github.com/ngcc-dev/ngcc-harness/issues/31)

The XOF wrapper accepts `digest_len_bits`, but passes its fixed `DIGEST_BIT_LENGTH = 1024` to `litchi_xof` instead (`Litchi-XOF/CryptHash_AlgorithmInstance.c:14–18` and its header). A caller requesting 512 bits and allocating the corresponding 64 bytes is therefore written 128 bytes. The output-size argument is not checked or honored. The XOF core can take a variable output length; this is a wrapper error, not an attack on the hash construction.

The fixed-output wrappers behave the same way. `Litchi-512`, `-768` and `-1024` never read `digest_len_bits` (`CryptHash_AlgorithmInstance.c:14–18` in each directory), return 0 and write their full 64, 96 or 128 bytes for 8- and 256-bit requests. This was added on 2026-11-17 after a survey of all hash wrappers.

### Reproducing

```sh
make -C hash-15
python3 hash-15/reproduce_xof_output_length.py
```

The native call requests 512 bits in a larger sentinel-backed buffer, confirms that bytes past the requested 64 change, and compares the entire result with a 1024-bit control request. It does not make an out-of-bounds allocation or infer exploitability from the overwrite.

For the fixed-output instances:

```sh
sh hash-15/reproduce_digest_length.sh
```
