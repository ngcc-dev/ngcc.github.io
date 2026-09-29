<!-- synchronized report: kem-18/report.md -->
Candidate: LoongKEM
Family: Lattice (LWE)
Archive: [LoongKEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/LoongKEM.zip) (SHA-256: `a6e5070647a40e7de1bf6e5b085dc1d6423c003a409864fdb303d87f881cec0b`)

## kem-18-1: Partial rejection mask leaks the candidate shared secret

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The decapsulator ORs ciphertext-byte differences into an arbitrary nonzero byte and negates that byte directly to form a selection mask. Except for the value `0x01`, this does not produce the required `0xff` mask. Invalid-ciphertext output is consequently a bitwise mixture of the candidate and fallback keys.

For all four parameter sets, changing ciphertext byte 1 by `0x80` produced an output retaining all seven low bits of every byte of the valid shared secret. Byte 0 is not a universal witness: at the 128- and 256-bit levels it produces only a partial mixture, while it works at the 384- and 512-bit levels. The byte-1 result was reproduced across ten independent key generations per parameter set.

An attacker modifies the IND-CCA challenge ciphertext and compares the retained positions with the challenge key. Agreement distinguishes the real key from a random key with overwhelming probability. This directly violates the claimed IND-CCA security of all four instances.

The comparison result must be normalized to a Boolean and expanded to exactly `0x00` or `0xff` before key selection.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-18
tools/ngcc_attack kem-reject-mask kem-18/lib/libLoong128.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## kem-18-2: Reducible rings project LoongKEM into much smaller SLWE instances

Severity: High
Status: Lead
Layer: Design
Affected: Loong128, Loong384, and Loong512; Loong256's `X^16+1` is integer-irreducible
Discovery: Moderate
Exploitation: Projected-secret recovery is estimated at 2^73.06, 2^103.34, and 2^203.74 operations; full key recovery remains estimator-only
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-28
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JHXFAJR6JLACWVD5ZIWPNP3H7N5OJOGG/)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §1](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

The specified rings split over the integers:

```text
X^12+1 = (X^4+1)(X^8-X^4+1)
X^20+1 = (X^4+1)(X^16-X^12+X^8-X^4+1)
X^24+1 = (X^8+1)(X^16-X^8+1).
```

The respective resultants are 81, 625, and 6561, all units modulo `q=8191`, so the two factors are also coprime over the scheme's field. The first public-key block row is entirely over this ring. Reducing it modulo either factor is therefore a public ring homomorphism that preserves shortness, while solving both quotient instances reconstructs the full PKE secret by CRT.

Using the exact alternating-fold secret distribution and a variance-matched model for the folded error and public-key rounding, the current MATZOV BDD estimator gives 73.06, 103.34, and 203.74 bits for the smaller components. These are far below Table 4's 147-, 398-, and 521-bit estimates, whose §5.3 analysis explicitly ignores the algebraic structure. Applying the same marginal model to the complementary components gives full-recovery estimates of 128.59, 365.51, and 399.31 bits; the latter two are below the named 384- and 512-bit targets.

This remains a Lead because coordinates in each complementary quotient have known correlations of magnitude `1/2`, while the standard estimator treats their marginals as independent. The exact decomposition, CRT reconstruction, covariance, and quoted estimator outputs are reproduced, but no covariance-aware full-size key recovery has yet validated the decisive complementary-component step. Under the classification policy, that missing step keeps this candidate-specific recovery path at High rather than Critical.

### Reproducing

Install Martin Albrecht's [lattice-estimator](https://github.com/malb/lattice-estimator) at audited commit `53da5982597709ba0fdf94ea37a84d822310fd84`, then run with a Python interpreter that provides `sage.all`:

```sh
LATTICE_ESTIMATOR_PATH=/path/to/lattice-estimator \
  mamba run -n sage python kem-18/reproduce_reducible_ring.py
```

The script checks the integer factorizations, coprimality modulo 8191, quotient homomorphisms, CRT reconstruction, and exact covariance matrices before reproducing the six MATZOV BDD estimates. Its final `LIMITATION` line records the correlation not modeled by those estimates.
