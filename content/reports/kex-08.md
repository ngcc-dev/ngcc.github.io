<!-- synchronized report: kex-08/report.md -->
Candidate: NIIKE
Family: Isogeny-based non-interactive key exchange
Archive: [NIIKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NIIKE.zip)

## kex-08-1: The raw shared j-invariant is distinguishable from a uniform key

Severity: High
Status: Confirmed
Layer: Design
Affected: NIIKE-lv128, -lv256, and -lv512 specification and reference API
Discovery: Moderate
Exploitation: Polynomial-time real-or-random distinguisher; no shared-key recovery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The specified `NIIKE.KeyAgr` (Algorithm 5, §4.3) returns the *unhashed* j-invariant of the shared supersingular curve. The submitted `kex_derive_ss_a/b` API likewise calls `niike_SecretAgreement` and serializes that field element directly with `fp2_encode`. An adversary given a candidate shared-key byte string can decode it as an element of Fp², construct a curve with that j-invariant, and test supersingularity. Every honest output passes. Only O(p) of the p² field elements are supersingular j-invariants, so a uniformly random canonical Fp² control passes with negligible probability. Uniform random API-length bytes are also distinguishable, even before the supersingularity test, because many are not canonical field encodings.

This is a real-or-random *key-distribution* break, not a method to compute the honest shared value from the public keys. It is a design error in the specified output, not an isogeny-path shortcut. The specification's §9.1.6 experiment samples its random branch from an abstract shared-key space `SK` without defining that space concretely. If `SK` were stipulated to be exactly the supersingular j-invariants with the honest distribution, this particular test would not distinguish that formal experiment. However, the proof of Theorem 9.1.7 explicitly analyzes a different construction that returns `H(K)` and compares it with a uniform hash output; Algorithm 5 and the shipped byte-key API perform no such hash. Therefore that proof does not establish uniform-byte key indistinguishability for the submitted construction.

The lv128 witness runs the official reference key generation and agreement for two honest parties, checks matching shared keys, then applies Sage's supersingularity test to the result and to 16 independently sampled *canonical* Fp² controls. It confirms an algebraic distinguisher independent of byte-encoding slack. The same raw-output data flow appears in all three levels; lv256/lv512 were not rerun in this witness because their reference group actions are much slower.

### Reproducing

Build the reference library and run the witness with Sage's Python:

```sh
make -C kex-08
sage -python kex-08/reproduce_raw_key_distinguisher.py
```

The witness prints `ATTACK kex-08-1 NIIKE-lv128 CONFIRMED` when the honest key is supersingular and all controls are ordinary.
