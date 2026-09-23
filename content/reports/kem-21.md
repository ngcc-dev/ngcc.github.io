<!-- synchronized report: kem-21/report.md -->
Candidate: MAMBA-Viper
Family: Lattice-based (Module-LWQ) KEM
Archive: [MAMBA-Viper.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/MAMBA-Viper.zip) (SHA-256: `cdf52bb77066664f74eb44872d5ab1785c22df194e50c603120432a169c61f4c`)

## kem-21-1: Viper-384 and -512 restrict the secret to a 256-bit seed

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: MAMBA-Viper-384 and MAMBA-Viper-512 reference implementations
Discovery: Trivial
Exploitation: At most 2^256 offline secret-seed trials against a public key
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The specification's Viper.PKE.KeyGen (Algorithm 3) samples the long-term secret vector coefficient-wise from the full centered-binomial distribution, and Table 3 claims 384- and 512-bit classical security for these profiles. Both submitted implementations instead draw a single 32-byte `sseed` and deterministically expand it with SHAKE256 into the entire secret vector `s`. The independent 32-byte `rho` only determines public `A` and its dither; it is copied into the public key.

For a target public key, an attacker can enumerate all 2^256 candidate `sseed` values, regenerate `s`, recompute the public quantized vector using the observed `rho`, and compare it with the public key. A matching seed gives the long-term PKE secret required to decapsulate valid ciphertexts. This caps the implemented 384- and 512-bit profiles at 256-bit offline key-search work regardless of the full-distribution lattice estimate. The attack violates both advertised security claims, hence the Critical severity. It is not an attack on the specification's ideal secret sampler, and a full 2^256 search was not run.

### Reproducing

```sh
python3 kem-21/reproduce_seed_ceiling.py
```

The static witness checks the 32-byte draw, the deterministic secret expansion, and the public-key construction in both reference source trees. It does not claim a practical full-size key recovery.
