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

The three signing algorithms increment `ctr` only when `chall3` fails the trailing-zero grinding condition. If that condition passes but `BAVC.Open` returns bottom because the opening exceeds `Topen`, the loop repeats with the same counter and otherwise unchanged hash input. It therefore derives the same challenge and rejects the same opening forever (SM4th.Sign lines 23–31, physical PDF page 60; uBlockith.Sign lines 22–30, page 71; Vistrutith.Sign lines 18–26, page 92).

The rejection branch is reachable. For SM4th-d3-128s-lo, the valid indices `(0,100,...,1000)` map to eleven leaf positions whose root-path union contains 135 nodes. The specified opening uses `135-2·11+1=114` sibling seeds, exceeding `Topen=102`. The tuple fits the 121 index bits and can be followed by the required seven zero grinding bits. This proves a specification-level non-progress case, not a practical chosen-message denial of service: no transcript producing that tuple was searched, and the inspected implementation advances the counter after a rejected batch.

### Reproducing

```sh
python3 sign-05/reproduce_open_retry.py
```

The witness recomputes every leaf position, the path-union size, and the opening-size rejection. Inspect the cited signing algorithms for the unchanged-counter retry.
