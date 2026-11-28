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

## kem-21-3: The E8 message codec is variable-time on decrypted values

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: All five MAMBA-Viper levels; reference and optimized implementations (all copies of `viper_e8.c` are identical)
Discovery: Moderate
Exploitation: Decapsulation's branch pattern and loop counts depend on the decrypted lattice point before the re-encryption check; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

Decapsulation decodes `v − sᵀu` with `viper_e8_decode` before the re-encryption check. The decoder is not constant-time. `d8_candidate` repairs parity only when the rounded coordinates have an odd sum (`viper_e8.c:141`) and then searches for the cheapest coordinate with data-dependent comparisons. `e8_rank` loops `for (v = 0; v < d[pos]; v++)` over each decoded digit and returns early on an invalid vector (`:72–88`). Each step reads `e8_count_cache` at an index formed from the running digit sum (`:35–38`). Encapsulation and re-encryption run `e8_unrank` on the message with an early `break` (`:51–69`). The specification states that all implementations are "structurally constant-time" (p. 4) and that message decoding avoids branching on secret data (§8.10, p. 27).

GCC 15.2 at the Makefile's `-O2` keeps conditional jumps at `viper_e8.c:141` and in the rank and unrank loops. The values that drive them derive from the private key and the ciphertext, so chosen ciphertexts change the trace before the validity decision. No oracle or recovery was built.

Constant-time fix (moderate): evaluate both parity cases and all digit positions with masks, and replace the rank loops by fixed-length table scans.

### Reproducing

```sh
d=kem-21/Implementations/Reference_Implementation/MAMBA-Viper-128
gcc -O2 -g -w -I"$d" -c "$d/viper_e8.c" -o /tmp/viper_e8.o
objdump -dl --no-show-raw-insn /tmp/viper_e8.o |
  awk '/^\/.*:[0-9]+/{loc=$1} /\tj[a-z]+ /{if ($2!="jmp") print loc, $2}' |
  grep -E 'viper_e8.c:(5[5-7]|7[6-9]|141)( |$)'
```

The listing shows conditional jumps attributed to the unrank loop, the rank loop and the parity test. No timing was measured.

## kem-21-4: Decapsulation never checks the ciphertext's `µ` field

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All five MAMBA-Viper levels; reference and optimized implementations
Discovery: Moderate
Exploitation: Ciphertexts with an arbitrary `µ` are accepted, so each message has many valid encryptions; no chosen-ciphertext attack demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

Algorithm 8 re-encrypts the decrypted message with coins `ω′` from `G(hpk, m′)` and accepts only if the result equals the received ciphertext. In the code, the coins are a seed `σ` and a 32-byte value `µ = H(K̄)` (`kem.c:39–41`). `µ` seeds the dither and part of the secret sampling, and is sent as the last field of the ciphertext.

`viper_reencrypt_check` does not recompute `µ`. It takes `µ` from the received ciphertext (`viper.c:562`), re-encrypts `u` and `v` under it, and then compares that pointer with the same ciphertext bytes (`:583`), which can never differ. Any `µ` therefore passes, provided `u` and `v` were formed with it. At every level, 50 of 50 ciphertexts built honestly except for a random `µ` returned the valid-path key.

Encryption as accepted is therefore not the deterministic function of `(m, G(hpk, m))` that the transform assumes: a party who knows `m` can produce 2^256 accepted ciphertexts for it. The shared key hashes the ciphertext, and forming `u` and `v` needs `m`, so we found no way to alter an honest ciphertext. The consequence for the IND-CCA argument is unresolved.

### Reproducing

```sh
sh kem-21/reproduce_mu_unchecked.sh
```

The witness checks the self-comparison in all ten trees, then builds each reference level and decapsulates 50 ciphertexts with an arbitrary `µ`. All must return the valid-path key; the same ciphertexts with one flipped bit of `u` must not.

## kem-21-5: The submitted E8 codec labels message blocks differently from the specified labelling

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All five MAMBA-Viper levels, reference and optimized implementations; Algorithms 1, 2, 9 and 10 of the specification
Discovery: Moderate
Exploitation: An implementation written from the specified labelling does not interoperate with the submitted code; the two maps were compared over every block value; no security consequence
Credit: Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, with MechCrypto assistance; labelling comparison by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/key-encapsulation/kem-21_MAMBA-Viper)

Algorithm 1 (physical p. 7) splits each message block into integers `a_0, …, a_7` of widths `β = (b−1, b, b, b, b, b, b, b+1)` and stores `Label_E8(a)`. Algorithm 9 (physical p. 26) defines the label as `λ = B_E8·a mod M·Z^8` for a displayed basis `B_E8`, with `M = 2^b`, and the text below it stores `α·λ mod q` with `α = q/M`. Algorithm 10 inverts the map with `B_E8^-1`.

The submitted code uses another bijection. `viper_e8_encode` reads the block as one integer `label` and stores `d[j]·(α/2)`, where `d = e8_unrank(label)` is the `label`-th vector, in lexicographic order, of `{0, …, 2M−1}^8` with equal parities and coordinate sum divisible by 4 (`viper_e8.c:49–70,91–96,176–188`). Decoding inverts it with `e8_rank` (`:72–89,190–203`). The file is identical in all ten trees.

Both maps reach the same `2^(8b)` cosets but assign them to different messages. Evaluated over every block value, they agree on 4 of 256 at `b = 1` (Viper-128, -192, -256) and on 4 of 65,536 at `b = 2` (Viper-384, -512). For the Viper-128 block with only message bit 0 set, Algorithm 9 gives `(2048, 2048, 0, 0, 0, 0, 0, 0)` and the code gives `(0, 0, 0, 0, 0, 0, 2048, 2048)`.

An implementation written from Algorithms 1, 2, 9 and 10 therefore produces different ciphertexts from the same message and coins, and each side decodes the other's ciphertexts to a different message and rejects them. Section 8.11 (physical p. 27) requires message encoding to match the reference output, so the written labelling cannot be followed. The reporters noted that the numbered Algorithms 1 and 2 omit the scaling by `α` and its inverse, which only the text of Section 8.8 supplies. There is no security consequence.

### Reproducing

```sh
pdftotext -f 26 -l 26 -layout kem-21/kem-21-spec.pdf - | grep -A6 'Algorithm 9'
sed -n '49,70p;176,188p' kem-21/Implementations/Reference_Implementation/MAMBA-Viper-128/viper_e8.c
```

This is a source witness. The comparison of the two maps was run with a driver around the archived `viper_e8.c` and is not part of it.
