<!-- synchronized report: kem-38/report.md -->
Candidate: UVW Key Encapsulation Mechanism
Family: Code-based
Archive: [UVW-KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/UVW-KEM.zip) (SHA-256: `f9a1b135ea16aca0c974861732e03cd3164f1288f33ff150ff66c98326b75bcb`)

Further analysis: [generic decoding and structural estimates](https://github.com/ngcc-dev/ngcc-harness/blob/main/kem-38/decoding_analysis.md) give context but establish no additional finding.

## kem-38-1: UVW-512 derives its encryption pair from only 256 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: UVW-KEM-512 reference and optimized implementations
Discovery: Trivial
Exploitation: Approximately 2^256 H1-seed trials
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

UVW-512 claims 512-bit classical security. The specification models `H1(m)` as a hash directly into the full encryption pair `(r,e)`, but the implementation first hashes `m` to a fixed 32-byte seed and then deterministically expands that seed into `(r,e)`.

An attacker can enumerate the at most `2^256` H1 seeds, expand each candidate `(r,e)`, and test the public equation `c1 = rG + e` against the challenge. A match recovers `m = c2 XOR H3(r,e)` and therefore the session key. This caps the implemented UVW-512 confidentiality at 256 classical bits and 128 quantum bits under generic search, independently of its nominal code-decoding parameters. The 256-bit intermediate is not specified by the PDF, so this is an implementation rather than specification-level break.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-38-1
```

The `kem-38-1` check verifies the 512-bit claim and `H1` type in the PDF and the 32-byte H1 seed in the submitted source.

## kem-38-2: UVW exposes a stable list-decoding failure oracle

Severity: High
Status: Confirmed
Layer: Design
Affected: UVW-KEM reference implementation, all parameter sets
Discovery: Trivial
Exploitation: Decryption-failure oracle; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The decapsulator returns `-2` when randomized PKE list decoding fails, but `-1` when decoding succeeds and a later hash or re-encryption check fails. These paths are also dramatically separated in time because the failing decoder exhausts its retry bound.

For one deterministic UVW-128 key and valid ciphertext, flipping ciphertext bit 0 returned `-2` after about 49.3 seconds; flipping bit 846 returned `-1` after about 0.81 seconds on the same host. Thus an attacker can distinguish a secret-dependent decoder failure through both API status and a roughly 60-fold timing gap. This supplies the oracle primitive used by reaction attacks, but this audit has not yet converted it into full secret-key recovery.

Constant-time fix (hard, hence High and Design): returning one status code is easy, but the timing gap comes from the randomized list decoder running to its retry bound on failure. The only known constant-time approach is to always do the failure path's work, about 49 s instead of 0.8 s per decapsulation in the measurement above. No competitive constant-time decoder is supplied or known, so the leakage is a property of the specified design rather than of this code.

### Reproducing

```sh
make -C kem-38 lib/libUVW-KEM-128.so
python3 security/kem_mutation_oracle.py \
  kem-38/lib/libUVW-KEM-128.so --bits 0,846
```

The seeds, mutations, return codes, and timings are deterministic. The slow `-2` witness takes about 50 seconds on the audit host.

## kem-38-3: Stateful timing reactions recover UVW-KEM-128 shared secrets

Severity: High
Status: Probable
Layer: Side-channel
Affected: UVW-KEM-128 reference implementation; higher sets not tested
Discovery: Non-trivial
Exploitation: About one million chosen-ciphertext decapsulation calls; 2.8 hours reported on 32 logical threads
Credit: Tianyuan Xie and Yamin Liu (openHiTLS team; with AI assistance)
Date: 2026-09-24
Original source: [NGCC PKC Forum post and attached reproducer](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/A6PUI23BHC7YNE5UQ3SMRO33GDBWCF2P/)
Follow-up source: [Black-box timing recovery and attached PoC](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XLK4PVBFDFWXQA4QXKNBPNQRKKITR5OW/)

UVW's secret monomial transform hides column pairs and their ratios. A chosen ciphertext whose error has a nonzero equal-scaled value in a hidden pair changes the list decoder's behavior. Conditioning public error samples on that reaction identifies pair/ratio triples; a public `Δ` projection then cancels the duplicated component, exposes a generalized Reed–Solomon image, and permits decoding a fresh ciphertext and deriving its exact 512-bit shared secret.

The follow-up removes the earlier observation-channel gap. `uvw_rs_list_decode` can return a positive candidate count without producing a valid `r2`, and `uvw_pke_dec` treats every positive count as success and continues with that state. A chosen primer ciphertext makes the leftover state repeatable; the following malformed target then takes either a fast path or an expensive recovery loop. The reporters measured about 0.12–0.17 seconds versus 14.5–15.2 seconds and used only the return code and wall-clock duration of unmodified `kem_dec`.

The PoC scans about 410,000 logical targets. Each sample consists of one primer and one target decapsulation, and confirmations bring the total to about one million calls. Its attack decisions consume only the public key, ciphertexts, and black-box timings; the locally generated secret key and honest shared secret are used to instantiate the decapsulation oracle and check the final answer. The reported 32-thread run ends with `success=1 shared_secret_match=1` after about 2.8 hours. Source inspection confirms this separation, and a clean independent replay reproduced the calibration but did not complete the full scan; the finding therefore remains Probable rather than Confirmed. Higher parameter sets and remote-network timing are untested. The attack is independent of weaknesses in the contest hash/XOF placeholders.

This complete shared-secret recovery shows that UVW-KEM-128 needs timing countermeasures. The submission does not claim that the list decoder or full decapsulation is constant-time, however, so the side-channel finding is High rather than Critical under the classification policy.

### Reproducing

Download the follow-up [forum attachment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XLK4PVBFDFWXQA4QXKNBPNQRKKITR5OW/attachment/4/poc.zip) (SHA-256 `0a7655e2b7f569d8f178db4bcfc59aa71b494331f5462aa54eb8607b1055c109`), unpack it, and follow its `README.md`. Use the source at ngcc-harness commit `fe1a9fe61348178218fce5e1a1f0c553b6e37f58`, or the byte-identical archived UVW-KEM-128 source. The principal commands are:

```sh
T=$(mktemp -d)
curl -fL -o "$T/poc.zip" \
  'https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/XLK4PVBFDFWXQA4QXKNBPNQRKKITR5OW/attachment/4/poc.zip'
printf '%s  %s\n' '0a7655e2b7f569d8f178db4bcfc59aa71b494331f5462aa54eb8607b1055c109' "$T/poc.zip" | sha256sum -c -
unzip -q "$T/poc.zip" -d "$T"
git clone https://github.com/ngcc-dev/ngcc-harness.git "$T/ngcc-harness"
git -C "$T/ngcc-harness" checkout fe1a9fe61348178218fce5e1a1f0c553b6e37f58
cd "$T/poc"
UVW_REF="$T/ngcc-harness/kem-38/Implementations/Reference_Implementation/UVW-KEM-128" \
  ./build_clean_blackbox_2026_09_28.sh
mkdir -p result
BB_NPROC=12 BB_PROBE_SHARDS=8 BB_SCAN_SHARDS=1000 \
  BB_STATE="$PWD/bb_state" \
  python3 run_blackbox_break_2026_09_28.py 2>&1 | tee result/blackbox-run.log
```

This is an hours-long CPU experiment. A successful run ends with `success=1 shared_secret_match=1`.

## kem-38-4: Unused c1 bits make ciphertexts malleable without changing the key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: UVW-KEM-128 and UVW-KEM-512 reference implementations; UVW-KEM-256 has no unused bits
Discovery: Trivial
Exploitation: One decapsulation query on a byte-distinct copy of the challenge ciphertext
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

The packed `c1` field ends with 4 unused bits, which `decompress_gf_array` ignores. Decapsulation compares the decoded `c1`, `c2` and `d` (`KEM_AlgorithmInstance.c:436,475–476` in UVW-KEM-128; `:433,480` in UVW-KEM-512), and the key is `H4(m', c1, c2)` over the decoded values (`:483` in 128; `:488` in 512). Setting any unused bit yields a different ciphertext with the same key. The submission claims IND-CCA security, which is trivially violated.

The specification's Algorithm 9 (§1.2.2) checks equality of the received `(c1, c2, d)` with the re-encryption before returning the key. It defines these as algebraic objects and gives no byte-padding rule. The alias enters through the submitted `decompress_gf_array` parser, which drops the unused bits before equality and key derivation.

### Reproducing

```sh
python3 kem-38/reproduce_padding_alias.py          # add 512 for UVW-KEM-512 (minutes)
```

## kem-38-5: The implementation's final decryption failures expose UVW's hidden pairs

Severity: High
Status: Lead
Layer: Implementation
Affected: UVW-KEM-128 reference implementation; the same 1,000-attempt cap is present in the higher sets
Discovery: Moderate
Exploitation: About 2^53 honest encapsulation/decapsulation trials for the UVW-128 pair-recovery stage
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/N2M32DODRHH53N6CQRXVSY3J77PZEWEK/)

The submitted decoder caps its information-set search at 1,000 attempts (`KEM_AlgorithmInstance.c:1256,1262,1354–1355` in UVW-128). Exact enumeration gives final-failure rates `2^-43.317`, `2^-42.144`, and `2^-41.729` for the 128-, 256-, and 512-bit implementations. An encapsulator knows the honest shared secret and can therefore recognize implicit rejection without a timing measurement. The specification's Algorithm 5 instead returns to Step 9 and chooses another information set without giving an attempt limit, so these final-failure rates are properties of the submitted implementation, not of the written algorithm.

Conditioning ciphertext errors on final UVW-128 failures exposes repeated coordinate pairs and their field ratios. A simulation using only 1,000 final failures recovered all 430 hidden pair/ratio triples; obtaining those failures costs about `2^(43.3+10) = 2^53.3` honest encapsulation/decapsulation trials. Tianyuan Xie and Yamin Liu demonstrated the public projection and generalized Reed–Solomon decoding stages needed for shared-secret recovery in their [openHiTLS UVW report and PoC](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/A6PUI23BHC7YNE5UQ3SMRO33GDBWCF2P/), but the timing-free artifact did not combine and rerun the complete recovery. The candidate-specific path is well below the 128-bit claim, but this remaining integration and scale gap makes the finding High and a Lead rather than a demonstrated primary break.

### Proposed fixes

The original post proposes stating the overall rather than per-attempt decryption-failure rate and including it in the Fujisaki–Okamoto bound. It says that making the rate negligible requires changing the decoder or parameters, rather than adding more retries.

### Reproducing

```sh
python3 kem-38/reproduce_dfr_reaction.py
```

The dependency-free witness recomputes all three exact rates and performs the failure-only 430-pair recovery. It does not execute the roughly `2^53` honest queries or the later key-recovery stages.

## kem-38-6: UVW-256 and -512 leak retry matrices

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: UVW-KEM-256 and UVW-KEM-512 reference implementations
Discovery: Trivial
Exploitation: Up to about 0.73 GB or 2.91 GB leaked by one 1,000-attempt decapsulation
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/N2M32DODRHH53N6CQRXVSY3J77PZEWEK/)

Every information-set retry allocates `GU_I1` and `GU_I1_inv`, each a `k1 * k1` matrix of 16-bit field elements, but neither the retry nor success path frees them (`KEM_AlgorithmInstance.c:1312–1336` for UVW-256 and `:1313–1336` for UVW-512). At 1,000 attempts this leaks about 0.73 GB for `k1=427` and 2.91 GB for `k1=853`. In UVW-256, the allocation-failure branch also calls `free(I1)` at line 1315 even though `I1` is a stack array, causing undefined behavior once allocation fails. UVW-128 places the matrices on the stack and does not have the retry leak. No memory disclosure or controlled write is demonstrated.

### Reproducing

```sh
python3 kem-38/reproduce_dfr_reaction.py
```

The witness checks both allocation paths and derives their byte counts from the archived parameters.

## kem-38-7: UVW-KEM resets the external DRBG for key expansion and re-encryption

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: UVW-KEM-128, -256 and -512 reference implementations
Discovery: Trivial
Exploitation: Serialized secret keys and FO re-encryption depend on the particular external RBG stream; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

Encapsulation derives `H1(m)` and resets an external DRBG to sample `(r,e)`; decapsulation repeats the reset from `H1(m')` before re-encryption (`KEM_AlgorithmInstance.c:312–330,411–426`). Secret-key parsing likewise reconstructs `GU`, `GW` and `D` by resetting local DRBG contexts from stored seeds (`:1485–1616`). Correctness and serialized-key interpretation therefore depend on one particular ICCS DRBG stream.

The archive is internally consistent and this finding adds no key recovery. The deterministic operations should use a specified XOF/PRG.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-38-7
```

## kem-38-8: Cubic-jet syzygies recover UVW's secret structure from the public key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: UVW-KEM-128, with key recovery and decapsulation demonstrated; UVW-KEM-256, where the distinguishing step is confirmed on a submitted key but recovery was not run; UVW-KEM-512 has the same structure, but neither step was run
Discovery: Non-trivial
Exploitation: From a UVW-KEM-128 public key alone, the twin pairing, scalings and Reed–Solomon description are recovered in under a minute on 28 cores, after which every ciphertext decapsulates in about 0.4 seconds; the method is polynomial in `n`
Credit: Liping Wang (wanglp, NGCC PKC Forum sender) for the cubic-jet distinguishing route; syzygy key recovery and full-size decapsulation by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-26
Original source: [Liping Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/D2DTPPLQWKGE3QZQCTDEMXYPKPGHXH4A/)

UVW's IND-CPA theorem (Theorem 3, physical p. 19) assumes that the Generalized (U+V, U+W) Code Distinguishing problem is hard (physical p. 16). The specification argues that distinguishing amounts to finding codewords of the form `(u,u)D`, and that this takes exponential time when `k1 = k2` (physical pp. 22–25). The forum post instead applies the order-2, degree-3 multiplicity method of [Ghoshal, Ishai, Jain and Sun](https://eprint.iacr.org/2026/1630) and [Weis](https://eprint.iacr.org/2026/1984) to shortened public codes of dimension `Θ(√n)`, and claims polynomial-time key recovery at all three levels without describing the extraction.

The distinguishing step works as described. Shorten the public code at `n/2 − k_l` random positions and view its `n'` columns as points in `F_q^{k_l}`. Then count the cubic forms whose gradient vanishes at every point, which by Euler's identity also vanish there to order two. For random points, this is the generic `max(0, C(k_l+2,3) − n'·k_l)`. On public keys from the frozen reference key generation, the count exceeds that by `k2 − k_l + 2`:

- UVW-KEM-128 at `k_l = 53`: 800 against 636.
- UVW-KEM-256 (`q = 857`, `n = 1708`) at `k_l = 74`: 1,983 against 1,628.

Random codes of the same shape give exactly the generic count. So does the twin structure with a random block in place of the Reed–Solomon generator, so the excess comes from the hidden Reed–Solomon component.

The excess also yields the secret structure. When the jet system has no more rows than cubic monomials, its row dependencies form a space of dimension `k2 − k_l + 2`. Split each dependency into one `k_l`-sized block per surviving column. A column whose twin also survives the shortening has rank-1 blocks, the twins carry the same coefficient vector, and the block direction lies on the line through the two columns. Its coordinates give the ratio of the twins' secret scalings. A column whose twin was shortened has rank-2 blocks. Three adaptive rounds pair all 430 twin classes of a UVW-KEM-128 key. Each round, at `k_l = 53`, finds a 164-dimensional dependency space of a 25,599 × 26,235 system in about 16 seconds.

Subtracting each scaled twin pair gives a `[430, 215]` code whose square has dimension 429, so it is a generalized Reed–Solomon code. Sidelnikov–Shestakov then recovers its support and multipliers up to the eight Möbius maps that fix the public complement `{0, 431, 432, ∞}` of `α = (1, …, 430)`. Each of the eight is a valid description of the code.

For a ciphertext, the attacker forms the same pairwise differences of `c1` and list-decodes them with the submitted Guruswami–Sudan decoder. The `w = 116` errors leave about 640 error-free coordinates, which determine `r` from `(I_k | T)`. That gives `e`, then `m = c2 ⊕ H3(r, e)`, the `d = H2(m)` check, the full `H1(m)` re-derivation and `K = H4(m, c1, c2)`.

The attack recovers an equivalent decapsulation description: the pairing, scalings and one of the eight Reed–Solomon descriptions. This is not necessarily the victim's byte-for-byte secret key, but it decapsulates the victim's ciphertexts. The following results come from separate local runs and were scored against the secret key, monomial map and sender secrets. None of these enters the attack.

- **Structure recovery:** on five fresh frozen UVW-KEM-128 key pairs, all 430 pairs and all 430 scaling ratios were correct. On the four keys where it was scored, one of the eight Reed–Solomon descriptions matched the secret support exactly, with proportional multipliers.
- **Decapsulation:** across four key pairs, the recovered key decapsulated 18 of 18 fresh ciphertexts to the sender's shared secret. Each passed the `d` check and the re-derivation.
- **Controls:**
  - A ciphertext under a different key pair fails to decode.
  - A flipped `c1` bit fails to decode.
  - A flipped `c2` bit fails the checks.
  - A random code yields no dependencies.

This breaks UVW-KEM-128 confidentiality from the public key alone, and refutes the code-distinguishing assumption at both measured levels. The jet system has `Θ(n^{1.5})` rows and columns, so dense elimination costs `O(n^{4.5})` per round. The post's figures for full key recovery, `2^53.68`, `2^57.75` and `2^61.56` bit operations, were not checked. UVW-KEM-256 key recovery and both UVW-KEM-512 steps were not run. They would need 68,672- and about 186,000-row systems respectively.

### Reproducing

```sh
sh kem-38/reproduce_jet_distinguisher.sh                 # scaled models and controls
NGCC_LONG=1 sh kem-38/reproduce_jet_distinguisher.sh     # adds a full-size UVW-KEM-128 count
sh kem-38/reproduce_key_recovery.sh                      # full UVW-KEM-128 key recovery
```

The distinguisher certificate counts jets for model keys at `n` = 140 and 200, with twin-shape and random controls that must match the generic count. Its long mode generates a fresh frozen UVW-KEM-128 public key and repeats the count at `n = 860`, `k_l = 53`, with a random control.

The key-recovery witness is a smaller check than the local runs above. It builds the frozen UVW-KEM-128 reference key generation and encapsulation (`uvw_sender.c`) and produces one key pair with three ciphertexts. It then recovers the structure from the public key alone (`uvw_key_recovery.c`) and decapsulates the ciphertexts with the submitted list decoder (`uvw_attack_decaps.c`). All three sender shared secrets must be reproduced. Three controls must fail: a ciphertext from a second key pair, a flipped `c2` bit, and a flipped `c1` bit. Recovery reads the secret monomial map only after the structure file is written, to score the pairing. The witness needs OpenMP and about 1.4 GB, and took about one minute on 28 cores. The UVW-KEM-256 count is not part of either script.
