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
Credit: OpenAI Codex (Daybreak Blue), disclosed by Martin Feussner
Date: 2026-09-25
Original source: [Feussner's pqc-forum post](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/_WrUbtphjHw/m/fHXYK5hJBAAJ) and attached analysis

The submission claims EUF-CMA security (§9.1.5–9.1.6), which is trivially violated: anyone can sign any message under any public key.

The specification binds the QuickSilver constant term into the final challenge, `chall3 ← H32(chall2 ∥ ã0 ∥ ã1 ∥ … ∥ ãd−1 ∥ ctr)` (SM4th.Sign line 24, physical PDF page 60; uBlockith line 23, page 71; Vistrutith line 19, page 92). The verifier reconstructs ã0 from the public key and the committed witness and recomputes that hash (SM4th.Verify lines 19–21, page 63). ã0 is the only value that depends on whether the committed witness satisfies the public one-way-function relation.

The implementations never hash ã0. `hash_challenge_3_init` absorbs `chall_2` and then `deg − 1` field elements starting at the signature's ã1 (`sm4th_d3_128f_loose/sig_impl.c:104-113`). The signer computes `a0_tilde` and frees it unused (`:440-458,516`). The verifier also computes it (`:652-658`), hashes only ã1…ãd−1 (`:670-671`), compares `chall_3` (`:675`), and frees `a0_tilde` (`:679`). uBlockith (`utils_ublock/sig_impl_ublock.c:203`) and Vistrutith (`utils_vistrutah/sig_impl_vistrutith.c:205`) do the same, as do all optimized copies. A forger therefore runs the ordinary signer with the victim's public key and a false witness, for example the extended witness of an all-zero key. All remaining commitment, consistency and grinding checks are honestly satisfied. Signer and verifier share the defect, so self-generated KATs pass.

### Reproducing

```sh
make -C sign-05 exploit
for b in sign-05/bin/reproduce_forgery_*; do "$b"; done
```

For each parameter set, the witness generates a victim key pair with `sig_keygen` and wipes the secret key. It checks that the all-zero OWF key is not a preimage of the public key, then signs with that key's witness while claiming the victim's OWF output. The public `sig_verify` accepts the forged signature, and a one-bit message change is rejected. Each set prints `ATTACK sign-05-1 <set> CONFIRMED`; all 14 were confirmed.
