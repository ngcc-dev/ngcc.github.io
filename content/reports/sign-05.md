<!-- synchronized report: sign-05/report.md -->
Candidate: Chinith
Family: Symmetric-key (VOLE-in-the-head) signature
Archive: [Chinith.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Chinith.zip) (SHA-256: `4d31ba3fe8718f59901b7efdf01b4179912ef8e04f58b4b6dbba84186f002283`)

## sign-05-1: The final Fiat–Shamir challenge omits ã0, allowing public-key-only universal forgery

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All 14 SM4th, uBlockith and Vistrutith parameter sets, reference and optimized implementations
Discovery: Moderate
Exploitation: No signing queries or secret information; one ordinary signing computation (0.01–6 s) per forged message
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/_WrUbtphjHw/m/fHXYK5hJBAAJ)
Follow-up source: [Chinith team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MJ6BBVT2VGSSN4YD45HOK4X7BPDDZ6UX/)

The submission claims EUF-CMA security (§9.1.5–9.1.6), which is trivially violated: anyone can sign any message under any public key.

The specification binds the QuickSilver constant term into the final challenge, `chall3 ← H32(chall2 ∥ ã0 ∥ ã1 ∥ … ∥ ãd−1 ∥ ctr)` (SM4th.Sign line 24, physical PDF page 60; uBlockith line 23, page 71; Vistrutith line 19, page 92). The verifier reconstructs ã0 from the public key and the committed witness and recomputes that hash (SM4th.Verify lines 19–21, page 63). ã0 is the only value that depends on whether the committed witness satisfies the public one-way-function relation.

The implementations never hash ã0. `hash_challenge_3_init` absorbs `chall_2` and then `deg − 1` field elements starting at the signature's ã1 (`sm4th_d3_128f_loose/sig_impl.c:104-113`). The signer computes `a0_tilde` and frees it unused (`:440-458,516`). The verifier also computes it (`:652-658`), hashes only ã1…ãd−1 (`:670-671`), compares `chall_3` (`:675`), and frees `a0_tilde` (`:679`). uBlockith (`utils_ublock/sig_impl_ublock.c:203`) and Vistrutith (`utils_vistrutah/sig_impl_vistrutith.c:205`) do the same, as do all optimized copies. A forger therefore runs the ordinary signer with the victim's public key and a false witness, for example the extended witness of an all-zero key. All remaining commitment, consistency and grinding checks are honestly satisfied. Signer and verifier share the defect, so self-generated KATs pass.

### Follow-up Analysis

The Chinith team confirms that every implementation must bind `a_tilde_0` through `a_tilde_(d-1)` and describes the omission as an implementation oversight. The same response lists three additional specification corrections concerning the `d=2`/`d=3`, EM/non-EM, and degree-lifting formulas; those errata are not separately classified here.

### Proposed fixes

The team's response proposes including every coefficient `a_tilde_0, ..., a_tilde_(d-1)` in both signing and verification. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C sign-05 exploit
for b in sign-05/bin/reproduce_forgery_*; do "$b"; done
```

For each parameter set, the witness generates a victim key pair with `sig_keygen` and wipes the secret key. It checks that the all-zero OWF key is not a preimage of the public key, then signs with that key's witness while claiming the victim's OWF output. The public `sig_verify` accepts the forged signature, and a one-bit message change is rejected. Each set prints `ATTACK sign-05-1 <set> CONFIRMED`; all 14 were confirmed.

## sign-05-2: Signing indexes lookup tables with the secret key

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: All 14 SM4th, uBlockith and Vistrutith parameter sets, reference and optimized implementations as built by default
Discovery: Trivial
Exploitation: Local cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-27

Key generation evaluates the one-way function on the secret key (`sm4th_d3_128f_loose/sm4th_d3_128f_loose.c:43`). Every signature re-derives its output and the extended witness from the secret key again (`:64,72`). The submitted Makefiles select table S-boxes (`sm4th_d3_128f_loose/Makefile:4`, `vistrutith_d3_512f/Makefile:4`, and `USE_SBOX_TABLE ?= 1` in the optimized trees). SM4th therefore reads the 256-byte `SM4_S` table at key-dependent round words (`utils_sm4/sm4_sbox.c:42-45`, `utils_sm4/sm4_core.c:208-216`). uBlockith reads eight 2-KiB T-tables in its middle rounds (`utils_ublock/ublock_core.c:61-62,137`); its comments acknowledge the Flush+Reload risk and harden only the first and last rounds. Vistrutith reads AES T-tables (`utils_vistrutah/vistrutah.c:37,105-134`). A co-resident cache observer can therefore see secret-key-dependent addresses on each signature. No key recovery is demonstrated.

Constant-time fix (easy, hence Low): the submission already contains table-free code. Building without `SM4_SBOX_TABLE` computes the SM4 S-box as an affine map, inversion by fixed exponentiation with masked multiplication, and another affine map (`utils_sm4/sm4_sbox.c:47-126`, `fields.c:253-286`). Vistrutith has a computed S-box path when `SBOX_TABLE` is undefined (`vistrutah.c:187`). Faster constant-time options are AES instructions between two `pshufb` affine transforms for SM4, AES instructions for Vistrutah, and a 16-entry in-register `pshufb` lookup for uBlock's 4-bit S-box.

### Reproducing

Inspect the cited build flags and table reads in any reference variant; the lookup indices are round words derived from the secret one-way-function key.

## sign-05-3: The specified opening-rejection retry cannot make progress

Severity: Low
Status: Confirmed
Layer: Design
Affected: SM4th, uBlockith, and Vistrutith signing pseudocode; concrete witness for SM4th-d3-128s-lo
Discovery: Moderate
Exploitation: A reachable challenge makes the specified signer loop forever; no efficient attacker trigger or implementation impact shown
Credit: changke
Date: 2026-09-30
Original source: [changke's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AGYNQF4QEWLJTPFESMNWASPA2BN6M7GL/)
Follow-up source: [Chinith team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6V7CWIE6JHSUTRBQK4U6BHNHEFAME76E/)

The three signing algorithms increment `ctr` only when `chall3` fails the trailing-zero grinding condition. If that condition passes but `BAVC.Open` returns bottom because the opening exceeds `Topen`, the loop repeats with the same counter and otherwise unchanged hash input. It therefore derives the same challenge and rejects the same opening forever (SM4th.Sign lines 23–31, physical PDF page 60; uBlockith.Sign lines 22–30, page 71; Vistrutith.Sign lines 18–26, page 92).

The rejection branch is reachable. For SM4th-d3-128s-lo, the valid indices `(0,100,...,1000)` map to eleven leaf positions whose root-path union contains 135 nodes. The specified opening uses `135-2·11+1=114` sibling seeds, exceeding `Topen=102`. The tuple fits the 121 index bits and can be followed by the required seven zero grinding bits. This proves a specification-level non-progress case, not a practical chosen-message denial of service: no transcript producing that tuple was searched, and the inspected implementation advances the counter after a rejected batch.

### Follow-up Analysis

The Chinith team confirms that the counter must advance after either grinding rejection or opening rejection. Its response also corrects the stated one-trial probability from `2^-wgrind` to `2^-wgrind·alpha`, where `alpha` is the probability that `BAVC.Open` accepts.

### Proposed fixes

The team's response proposes breaking only after both the grinding test and `BAVC.Open` succeed, returning failure if the 32-bit counter is exhausted, and otherwise incrementing the counter before retrying. This records the proposal without evaluating it.

### Reproducing

```sh
python3 sign-05/reproduce_open_retry.py
```

The witness recomputes every leaf position, the path-union size, and the opening-size rejection. Inspect the cited signing algorithms for the unchanged-counter retry.

## sign-05-4: uBlockith-EM witness misalignment reduces the specified relation to a two-round fixed point

Severity: Critical
Status: Probable
Layer: Design
Affected: Specified uBlockith-EM 256s and 256f; the submitted source has the corresponding completeness failure after binding the final Fiat–Shamir constant term
Discovery: Hard
Exploitation: Spec-literal universal forgery estimated at about 2^135.5 work; the 2^108 guess enumeration was not run
Credit: IIE-AIC Team
Date: 2026-09-30
Original source: [IIE-AIC Team's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/Q5TTRVDKJ2I2AZUK3YHZWORRNX6O27CN/) and [pinned artifact](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/729616512528d6e8aa06e85707e68cd4cf09a62a/chinith-em-misalignment)

The specification's 3,072-bit EM encryption witness begins with the secret input `S0`, yet `uBlockith.OWFConstraints` selects the encryption witness from offset `l_ke=0`, and `uBlockith.EncCstrnts` prepends the same input again (Table 2 and physical PDF pages 67–69). The checked chain is therefore

```text
S0 || S0 || S2 || ... || S22 || out.
```

Its first constraint is only `DoubleRound_0(S0)=S0`; the remaining constraints follow freely chosen intermediate blocks, and the loop stops at `S22` without reading `out=S0 xor pk2`. Thus the specified relation does not bind the public output. A fixed point of the first two public-keyed uBlock rounds gives a witness for any `pk2` and any message.

The posted guess-and-determine method fixes 108 nibble-spread input bits and SAT-solves the residual system. At this same `g=108` point, eight wrong guesses for a real public first component took 17.1 seconds on average, while the planted-instance mean was 22.3 seconds. This gives the reported extrapolation `2^108 · 2^27.5 = 2^135.5` double-round evaluations. The full enumeration was not run, so the empirical cost remains Probable, but the real-key measurement directly supports the extrapolation and its large margin below the claimed 256-bit level supports Critical severity.

### Further extension to IIE-AIC Team's analysis

The artifact estimates that about `1-1/e ≈ 63%` of public first components have a fixed point under the random-permutation heuristic. Accounting also for the independent `w[0]·w[1]=0` constraint thins the expected fixed-point count from 1 to `3/4`, so about `1-exp(-3/4) ≈ 53%` of first components are expected to have an admissible fixed point. This changes the affected-key fraction, not the attack cost when such a point exists.

The source duplicates the first witness block too (`ublockith_ublock_256.c:181,190,264`; `ublock_constraints.c:778–784`), but its final-round branch reads `out` directly. It therefore does not have the spec-literal forgery relation. Instead, once the final Fiat–Shamir challenge is corrected to bind the reconstructed constant term, honest uBlockith-EM signatures fail. The post reports this for both parameter sets and implementation families; our reference-256f replay obtained 0/5 valid signatures, while the non-EM control and a one-block-offset repair each gave 5/5.

### Proposed fixes

The post proposes either selecting the EM encryption witness after `S0` or not prepending `in` inside `EncCstrnts`. This records the proposal without evaluating it.

### Reproducing

```sh
sh sign-05/reproduce_em_constraints.sh
```

The wrapper downloads the public artifact at a pinned commit, applies its instrumentation only to temporary copies of the archived source, checks the uBlock core against its public vector, and replays the non-EM, EM, and shifted-witness controls. It also validates the clear constraint reduction for two unrelated public outputs. The final `LIMITATION` line records that the `2^135.5` estimate is an extrapolation rather than a completed enumeration.

## sign-05-5: Vistrutith combines three constraint families as one polynomial

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Vistrutith 512s and 512f, reference and optimized implementations
Discovery: Moderate
Exploitation: Honest signatures fail once the final Fiat–Shamir constant term is bound; no forgery is demonstrated
Credit: IIE-AIC Team
Date: 2026-09-30
Original source: [IIE-AIC Team's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/Q5TTRVDKJ2I2AZUK3YHZWORRNX6O27CN/) and [pinned artifact](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/729616512528d6e8aa06e85707e68cd4cf09a62a/chinith-em-misalignment)

Vistrutith creates three separate arrays of normal, input/output-0, and input/output-1 constraints. The prover passes one tag from each array to `zk_hash_SSS_3_update` as though they were the three coefficients of one degree-two polynomial (`vistrutith_vistrutah_512.c:139–145`). The verifier correspondingly hashes `z_norm + delta·z_io0 + delta^2·z_io1` (`:163–170`). This is not the coefficient decomposition of any one submitted constraint and loses the intermediate coefficients of the three actual constraint polynomials. The file is byte-identical in both parameter sets and implementation families.

After instrumenting signing and verification to bind the reconstructed constant term, honest Vistrutith-512f signatures failed 5/5. A clear-value control simultaneously found zero nonzero values in each of the three 576-element constraint arrays, excluding an invalid witness as the cause. The current final-challenge omission masks this independent completeness error. No forgery or security-level reduction follows, so the finding is Low.

### Reproducing

```sh
sh sign-05/reproduce_em_constraints.sh
```

The Vistrutith portion prints five signer/verifier constant-term mismatches, followed by two controls in which all 1,728 honest constraint values are zero.
