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
Credit: mmtobs, with AI assistance
Date: 2026-09-25
Original source: [ngcc-harness pull request #17](https://github.com/ngcc-dev/ngcc-harness/pull/17)

Specification Algorithms 12 and 14 unpack fixed-width coefficient fields without rejecting values at least `q`, and Algorithm 3 never rechecks the received ciphertext bytes. The reference `poly_frombytes` does the same (`poly.c:104`). When a ciphertext coefficient `c + q` still fits its field, replacing `c` with `c + q` changes the ciphertext bytes but leaves the polynomial residue used by decapsulation unchanged. `kem_dec` checks the confirmation tag but never checks that the received polynomial bytes are canonical (`KEM_AlgorithmInstance.c:170–204` in OAEP-NTRU-648, `:215–249` in -1296, and `:185–228` in -2592). A modified encoding of an honest ciphertext therefore returns its original shared secret. In the IND-CCA game, this byte-distinct alias can be submitted to the decapsulation oracle even though the challenge ciphertext itself cannot.

### Reproducing

Run `python3 kem-28/reproduce_noncanonical_ciphertext.py` against the built harness libraries. This independent witness reproduced 5/5 accepted `+q` aliases at each of the three levels (15/15 total), all with return code 0 and the honest shared secret. None of the 15 non-congruent `+q+1` controls returned that key. [PR #17](https://github.com/ngcc-dev/ngcc-harness/pull/17) separately reports 10/10 aliases per level; its code remains unmerged. The optimized and additional decoder omissions were checked in source, not executed by this witness.
