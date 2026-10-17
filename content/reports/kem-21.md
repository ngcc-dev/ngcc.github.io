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

## kem-21-2: Viper-384 and -512 derive the encapsulation secret from a 256-bit seed

Severity: Critical
Status: Confirmed
Layer: Design
Affected: MAMBA-Viper-384 and MAMBA-Viper-512, specification and all reference and optimized implementations
Discovery: Trivial
Exploitation: Shared key recomputed from (pk, ct) and the 32-byte σ alone, 20/20 per level, and recovered by a reduced 2^16 σ search; the full 2^256 enumeration was not run
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Viper.PKE.Enc (Algorithm 4, p. 8) takes coins ω ∈ {0,1}^512 and parses them as ω ↦ (σ, µ) ∈ {0,1}^256 × {0,1}^256 for every profile. The ephemeral secret is r ← GenSecret(σ), and µ, which only fixes the ciphertext dithers, is transmitted in the ciphertext. Viper.KEM.Encaps (Algorithm 7, pp. 9–10) feeds these coins from (K̂, ω) ← G(H(pk), m). Once r is known, m can be decoded from the ciphertext with public values, so every secret of the session hangs on 256 bits, while the 384- and 512-bit profiles target 384 and 512 bits (Table 2, p. 4, with MATZOV estimates of 410.2 and 564.6 bits). The submitted code follows the specification in effect. `kem.c:39–42` derives a σ of |K| bytes (48 or 64) and copies it into ω, but `viper_sample_secret` absorbs only `seed, 32` (`viper.c:425,437` in the reference trees, `viper.c:468,480` in the optimized trees), so the remaining 16 or 32 bytes never influence the ciphertext.

Given a public key and a ciphertext, an attacker enumerates σ ∈ {0,1}^256. For each candidate it computes r = GenSecret(σ), decodes m = Decode(v̂ − b̂ᵀr) using only public values, recomputes (K̂, σ′) = G(m ‖ H(pk)), and accepts when σ′ matches the candidate. The accepted m gives K = H(K̂, H(ct)). Each trial costs one sampler expansion, one module inner product and one hash. No decapsulation query and no secret-key information are needed, and the search is per session and passive. This recovers any Viper-384 or Viper-512 shared key in about 2^256 classical work, below both claimed levels, hence the Critical severity.

The defect lies in the specified coin width, not in a coding error, so it is independent of how the long-term secret key is generated and survives any change to key generation. All five reference and five optimized trees share `kem.c`, and their samplers read 32 seed bytes. At Viper-128, -192 and -256 the same search costs 2^256, which is at or above the target, so those profiles are not affected. A full 2^256 search was not run. The reproducer supplies σ by replaying the encapsulator's DRBG, standing in for the guess that the enumeration would find.

### Reproducing

```sh
sh kem-21/reproduce_sigma_ceiling.sh
```

The script checks that the sampler and `kem.c` are shared by all ten trees. It then builds an attacker harness from an unmodified copy of each reference tree in a temporary directory and runs key generation, encapsulation and decapsulation in the prebuilt `kem-21/lib` libraries. At Viper-384 and -512 it recomputes the library's shared key from (pk, ct, σ[0..31]) in 20/20 sessions, checks that inverting ω bytes 32 onward leaves the ciphertext unchanged, and recovers the key by a 2^16 search over the low bits of σ with the rest given as a hint. Controls: honest decapsulation matches, a one-bit-wrong σ prefix is rejected, and Viper-256 is run to show that its σ width equals its target. It takes about 55 seconds; `NGCC_LONG=1` widens the search to 2^20 (about 15 minutes).
