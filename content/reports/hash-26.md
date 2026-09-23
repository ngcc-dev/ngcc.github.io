<!-- synchronized report: hash-26/report.md -->
Candidate: The Hash Function CHIME
Family: Symmetric (sponge and feed-forward sponge)
Archive: [CHIME.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/CHIME.zip) (SHA-256: `3368eff8f86744eefba82825c11990a3b4d914e014ff184324ab3cb9af88b3a4`)

## hash-26-1: An invariant subspace reduces CHIME collision bounds to 64 and 224 bits

Severity: High
Status: Confirmed
Layer: Design
Affected: Submitted CHIME-512 and CHIME-1024 specifications and implementations
Discovery: Moderate
Exploitation: Approximately 2^64 and 2^224 evaluations; no collision has been computed
Credit: Cryptanalysts001 (ISCAS) <yufei2021@iscas.ac.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/5UIMK76TG55NELJD44XE7QVM2OPURHCK/)

In the submitted permutation, each 256-bit array remains in the repeated-word form `(x,x,x,x)`: every layer preserves it and each round constant repeats one 64-bit word four times. This gives a 384-dimensional invariant subspace for the complete nonlinear, full-round permutation.

For CHIME-512, a `2^240`-message family remains in the subspace through ordinary padding, while its digest contains only two independent 64-bit words. Sampling this family therefore gives a classical collision upper bound of about `2^64`, rather than the claimed 256 bits. For CHIME-1024, eight controlled blocks encode `2^512` distinct messages but reach at most `2^448` pre-final states; common padding and finalization preserve equality, giving an upper bound of about `2^224`, rather than 512 bits. These are proof-level squeeze bounds, not computed collisions.

The submission team subsequently published an [erratum](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/HLW3FPCIRT2UIR3YMYJJ5YW7SCGZENUL/) changing the repeated round constants to word-dependent constants. That acknowledges and removes this particular invariant in a revised design; the archived Round 1 submission remains affected.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/2026/2152), Section 5 (2026-09-23), gives a greater-than-0.39 collision probability within `2^64` evaluations for CHIME-512. The paper does not cover this report's CHIME-1024 extension.

### Reproducing

The local check reproduces the reporters' 126-byte CHIME-512 invariant-state witness and digest and recomputes both dimension bounds:

```sh
make -C hash-26 reproduce
```
