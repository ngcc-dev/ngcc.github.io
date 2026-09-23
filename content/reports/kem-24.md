<!-- synchronized report: kem-24/report.md -->
Candidate: MORNING-Scabbard
Family: Lattice (Module-LWR)
Archive: [MORNING-Scabbard.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/MORNING-Scabbard.zip) (SHA-256: `fdb6749116bddbb8a86074b9ab6f5f55d37540b92e3964906dede0b09c7faf4b`)

## kem-24-1: Encryption omits the specified rounding constant

Severity: Medium
Status: Probable
Layer: Implementation
Affected: Reference implementation, scabbard128 and scabbard256
Discovery: Trivial
Exploitation: Not yet demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Algorithm 10 forms encryption component `u` by adding the constant `h` before the `q`-to-`p` right shift, implementing nearest rounding. The scabbard128 and scabbard256 reference implementations omit `+h` and truncate instead. The scabbard512 source contains the specified addition and provides a direct comparison.

Re-encryption repeats the same altered operation, so functional KATs and the Fujisaki-Okamoto equality check remain internally consistent. Nevertheless, the ciphertext distribution and decryption-noise law differ from those used by the specification's correctness, decryption-failure, and IND-CPA analyses.

This is a confirmed implementation/specification mismatch in two of three parameter sets. No concrete distinguisher or key-recovery attack has yet been derived from the changed distribution, so the report does not claim a complete confidentiality break.

### Reproducing

This is a source review, not a runnable attack. Fetch the official archive and
compare the encryption-component `u` rounding in the three reference variants:

```sh
IDS=kem-24 ./download.sh
./extract.sh kem-24
for level in 128 256 512; do
  sed -n '60,72p' "kem-24/Implementations/Reference_Implementation/scabbard${level}/indcpa.c"
done
```

The `u` shift is at lines 69, 67, and 69 respectively; only scabbard512 adds
`h1` first. Compare Algorithm 10 in `kem-24/kem-24-spec.pdf`.
