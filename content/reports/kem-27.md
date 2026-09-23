<!-- synchronized report: kem-27/report.md -->
Candidate: NTRE
Family: Lattice-based (NTRU) KEM
Archive: [NTRE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NTRE.zip)

## kem-27-1: NTRE-512's 256-bit secret seed caps offline key-recovery work

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: NTRE-512 reference implementation
Discovery: Moderate
Exploitation: At most 2^256 seed trials against a public key, versus the 512-bit target
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

NTRE-512's reference key generator samples the private NTRU polynomial `f = 2f' + 1` from a single 32-byte seed through `sample_psi1`. This restricts its nominally 512-bit secret-key space to at most 2^256 possibilities. The public key permits an efficient offline test of each guess: compute `g = h·f` and check whether its coefficients have the required small distribution (`g = 2g'`). A surviving `f` is sufficient to reconstruct the decapsulation key (`f`, the public key, and its public hash). Thus exhaustive seed search recovers a working key in at most 2^256 trials, independent of the claimed hardness of the full-distribution NTRU problem.

This is an implementation-instantiation weakness, not a claim that the specification's ideal `Sample(n)` has only 256 bits of entropy. The full 2^256 search is far beyond available resources. A scaled public-key attack enumerates 2^12 planted seed candidates, finds the unique matching `f`, reconstructs the official secret-key layout and correctly decapsulates ten fresh ciphertexts; ten deliberately wrong-key controls fail.

### Reproducing

```sh
make -C kem-27 exploit
```

The script builds the submitted NTRE-512 sources in a temporary directory and prints `CONFIRMED kem-27-1`. It explicitly labels the scaled seed subspace and does not present this as a full-size key recovery.
