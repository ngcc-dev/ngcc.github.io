<!-- synchronized report: hash-26/report.md -->
Candidate: The Hash Function CHIME
Family: Symmetric (sponge and feed-forward sponge)
Archive: [CHIME.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/CHIME.zip) (SHA-256: `3368eff8f86744eefba82825c11990a3b4d914e014ff184324ab3cb9af88b3a4`)

## hash-26-1: An invariant subspace reduces CHIME collision bounds to 64 and 160 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Submitted CHIME-512 and CHIME-1024 specifications and implementations
Discovery: Moderate
Exploitation: Approximately 2^64 and 2^160 evaluations; no full collision has been computed
Credit: Cryptanalysts001 (ISCAS) <yufei2021@iscas.ac.cn>; CHIME-1024 extension and CHIME-512 partial-collision witness by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/5UIMK76TG55NELJD44XE7QVM2OPURHCK/)

In the submitted permutation, each 256-bit array remains in the repeated-word form `(x,x,x,x)`: every layer preserves it and each round constant repeats one 64-bit word four times. This gives a 384-dimensional invariant subspace for the complete nonlinear, full-round permutation.

For CHIME-512, a `2^240`-message family remains in the subspace through ordinary padding, while its digest contains only two independent 64-bit words. Sampling this family therefore gives a classical collision bound of about `2^64`, rather than the claimed 256 bits. For CHIME-1024, the 448-bit rate occupies `A0` and three lanes of `A1`; the remaining `A1[0]` and four `B/C` arrays form the capacity (`CryptHash_AlgorithmInstance.c:780–815,829–867`). Before each non-final permutation, choosing repeated words in `A0` and adjusting the three rate lanes of `A1` restores the invariant subspace, leaving 64 free message bits per block. Six controlled blocks thus give `2^384` distinct prefixes, but their capacities have only five independent 64-bit words. Sampling about `2^160` such prefixes yields a capacity match with probability above 0.39 for any output distribution; repeated prefixes contribute less than `2^-64`. One further chosen block cancels the rate difference, and equal old capacities make the feed-forward outputs and final digests equal. This strengthens the earlier `2^224` bound. The full-size search has not been run.

A separate search produced two distinct 63-byte CHIME-512 messages whose first 256 digest bits agree under the submitted 15-round reference hash; the remaining 256 bits differ. It took `2^32.95` folded-permutation evaluations. This is a partial collision, not a full collision.

The archived Round 1 submission remains the target of this finding.

Further analysis: [Yufei Yuan et al., *Structural Analysis of Seven Hash Functions Submitted to the NGCC*](https://eprint.iacr.org/archive/2026/2152/20260923:103749), Section 5 (2026-09-23), gives a greater-than-0.39 collision probability within `2^64` evaluations for CHIME-512. The paper does not cover this report's CHIME-1024 extension.

### Proposed fixes

The submission team's [erratum](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/HLW3FPCIRT2UIR3YMYJJ5YW7SCGZENUL/) proposes replacing the repeated round constants with word-dependent constants. This section records the proposal without evaluating it.

### Reproducing

The local checks reproduce the reporters' 126-byte CHIME-512 invariant-state witness, verify the 256-bit partial collision on the submitted reference hash, and use the submitted CHIME-1024 source to test restricted chaining and chosen-block rate alignment. They do not execute either full collision search:

```sh
make -C hash-26 reproduce
python3 hash-26/reproduce_capacity_match.py
```
