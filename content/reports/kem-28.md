<!-- synchronized report: kem-28/report.md -->
Candidate: OAEP-NTRU
Family: Lattice (NTRU)
Archive: [OAEP-NTRU.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/OAEP-NTRU.zip) (SHA-256: `aaab8e0692fd19dd2edda5384b5e85bba74661d478823b48cab3cccb53675756`)

## kem-28-1: Noncanonical ciphertext encoding defeats IND-CCA security

Severity: Critical
Status: Confirmed
Layer: Design
Affected: OAEP-NTRU-648, -1296, and -2592 reference implementations; the same decoder omission is present in the submitted optimized and additional sources
Discovery: Trivial
Exploitation: One decapsulation query for a byte-distinct encoding of an honest challenge ciphertext
Credit: Matthias Meijers (GitHub @mmtobs), with AI assistance
Date: 2026-09-25
Original source: [ngcc-harness pull request #17](https://github.com/ngcc-dev/ngcc-harness/pull/17)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-28 revision, §4](https://eprint.iacr.org/archive/2026/2232/1790581014.pdf)

Specification Algorithms 12 and 14 unpack fixed-width coefficient fields without rejecting values at least `q`, and Algorithm 3 never rechecks the received ciphertext bytes. The reference `poly_frombytes` does the same (`poly.c:104`). When a ciphertext coefficient `c + q` still fits its field, replacing `c` with `c + q` changes the ciphertext bytes but leaves the polynomial residue used by decapsulation unchanged. `kem_dec` checks the confirmation tag but never checks that the received polynomial bytes are canonical (`KEM_AlgorithmInstance.c:170–204` in OAEP-NTRU-648, `:215–249` in -1296, and `:185–228` in -2592). A modified encoding of an honest ciphertext therefore returns its original shared secret. In the IND-CCA game, this byte-distinct alias can be submitted to the decapsulation oracle even though the challenge ciphertext itself cannot.

### Reproducing

Run `python3 kem-28/reproduce_noncanonical_ciphertext.py` against the built harness libraries. This independent witness reproduced 5/5 accepted `+q` aliases at each of the three levels (15/15 total), all with return code 0 and the honest shared secret. None of the 15 non-congruent `+q+1` controls returned that key. [PR #17](https://github.com/ngcc-dev/ngcc-harness/pull/17) separately reports 10/10 aliases per level; its code remains unmerged. The optimized and additional decoder omissions were checked in source, not executed by this witness.

## kem-28-2: Decapsulation returns the tag difference and writes the key before rejecting

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: OAEP-NTRU-648, -1296 and -2592; reference, optimized and additional implementations
Discovery: Moderate
Exploitation: For a ciphertext body that passes the range and SOTP checks, the return value reports each tag bit plane's match separately; a rejected call also leaves the derived key in the output buffer. No tag recovery for a chosen body, key recovery or IND-CCA attack demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

Algorithm 3 recomputes `(σ′, k′) = H(d‖s‖e)` from the decrypted pair and returns ⊥ unless `σ′` equals the received tag and the SOTP check passes (lines 14–16). The tag is what stops a chosen ciphertext body from being accepted. The submitted `kem_dec` accumulates the comparison as `fail |= ct[i] ^ sigma[i]` into an `int8_t`, copies `k′` to the caller's buffer unconditionally, and returns `fail` (`KEM_AlgorithmInstance.c:202–209` in reference OAEP-NTRU-648; the same three statements are in all nine trees).

Two things follow. First, the return value is the bytewise OR of the tag difference, not a validity bit: bit `b` is clear exactly when bit `b` of every tag byte matches. Flipping tag bit 0, 1, …, 7 of one byte of an honest ciphertext returns 1, 2, …, 64 and −128. A caller that reports the return code therefore reveals more than accept or reject: on a body that passes the other checks, the tag comparison leaks per bit plane instead of all-or-nothing. Bit 0 also carries the range and SOTP checks (`:184,190`), so for a body that fails either of them bit 0 stays set whatever the tag, and planes 1–7 are the only tag information. We observed the per-plane behaviour only on honest ciphertext bodies. Second, the rejected call has already written `k′`: with a wrong tag on an honest body, the output buffer holds the honest shared secret. A caller that reads the buffer without checking the return code gets the key the specification withholds.

The return value thus weakens the confirmation tag from an all-or-nothing check to one that leaks per bit plane, and the output buffer exposes a key the specification withholds. We did not show recovery of a complete tag for a chosen body, an accepted chosen ciphertext, or a key-recovery or IND-CCA attack. A caller that treats every nonzero return alike and discards the buffer is not affected. The consequence is unresolved, hence Medium.

### Reproducing

```sh
sh kem-28/reproduce_tag_return.sh
```

The witness checks the three statements in all nine trees, then builds each reference level and flips each bit of one tag byte of an honest ciphertext. It requires the eight return values 1, 2, …, 64, −128, the honest shared secret in the output buffer each time, and return 0 for the unmodified control. No tag search is run.
