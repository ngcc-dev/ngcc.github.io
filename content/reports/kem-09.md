<!-- synchronized report: kem-09/report.md -->
Candidate: CheetahKEM
Family: Lattice (Ring/Module-LWE)
Archive: [CheetahKEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CheetahKEM.zip) (SHA-256: `fc321e46bac9c387535e2053bed560eac3d3cd88ba9bebc154f5bf68dd47dcd1`)

## kem-09-1: Partial rejection mask leaks the candidate shared secret

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The decapsulator ORs ciphertext-byte differences into an arbitrary nonzero byte and then uses its negation directly as a selection mask. Negating a nonzero byte produces `0xff` only when that byte is `0x01`; other values select a bitwise mixture of the valid candidate key and the rejection key.

For all four parameter sets, changing ciphertext byte 1 by `0x80` produced a rejection output retaining all seven low bits of every byte of the valid shared secret. Byte 0 is not a universal witness: at the 128- and 256-bit levels it produces only a partial mixture, while it works at the 384- and 512-bit levels. The permanent `kem-reject-mask` test reproduced a byte-1 witness for every tested key generation.

An IND-CCA attacker modifies the challenge ciphertext and compares the retained bit positions with the challenge key. For a real challenge they agree; for a random challenge the false-match probability is negligible. This is a direct distinguisher against all four claimed IND-CCA instances.

The fix is to normalize every nonzero comparison result to an all-ones mask before selecting between the candidate and rejection secrets.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C kem-09
tools/ngcc_attack kem-reject-mask kem-09/lib/libCheetah128.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## kem-09-2: A degree-128 quotient defeats the full-dimension MLWE estimates

Severity: High
Status: Lead
Layer: Design
Affected: All four parameter sets
Discovery: Moderate
Exploitation: Estimated at 2^27.7, 2^67.7, 2^99.3, and 2^133.4 operations
Credit: XuHaomeng
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/IKMFXEEH5K427JC75E7364RNOJEO5OK7/)

The specified ring polynomial is reducible: `X^640+1 = (X^128+1)(X^512-X^384+X^256-X^128+1)`. Reducing a public MLWE sample modulo `X^128+1` is the public alternating fold `a[j]-a[j+128]+a[j+256]-a[j+384]+a[j+512]`. It reduces the scalar secret dimension from `640k` to `128k`; five independent `CBD(eta)` coefficients fold to `CBD(5*eta)`, and public-key compression noise folds in the same way.

Re-running `lattice-estimator` with that quotient distribution reproduces XuHaomeng's [mailing-list estimates](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/IKMFXEEH5K427JC75E7364RNOJEO5OK7/): uSVP costs of 27.7, 67.7, 99.3, and 133.4 bits, versus the specification's 159, 307, 426, and 541 bits. This establishes a much cheaper distinguisher for the underlying structured samples and invalidates estimates that treat all `640k` coordinates as one irreducible component.

This remains a Lead because a complete IND-CCA attack on the KEM has not been constructed. Full secret recovery also requires solving the residual degree-512 component; the post explicitly leaves that cost unresolved.

### Reproducing

Install Martin Albrecht's [lattice-estimator](https://github.com/malb/lattice-estimator)
at the audited commit `53da5982597709ba0fdf94ea37a84d822310fd84`, then run
the script with Sage's Python and point it at that checkout:

```sh
LATTICE_ESTIMATOR_PATH=/path/to/lattice-estimator \
  mamba run -n sage python kem-09/reproduce_quotient_estimate.py
```

The script checks the factorization and quotient homomorphism, then instantiates the estimator with the folded secret, error, and compression distributions.
The command uses this host's Sage environment; elsewhere, any Python with `sage.all` importable can run the script with `LATTICE_ESTIMATOR_PATH` set.

## kem-09-3: Cheetah's decryption-failure analysis omits public-key rounding

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All four CheetahKEM parameter sets
Discovery: Moderate
Exploitation: Submitted failure estimates omit a noise term; actual DFR and attack impact unmeasured
Credit: Yijian Liu (with AI assistance)
Date: 2026-09-24
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5TLZROCK6ZQKG6HTV3PNNESJKICDDKGE/)

Algorithm 15 publishes `b' = Compress(A·s+e)`, and Algorithm 16 encrypts with `Decompress(b')`. Writing the nonzero public-key rounding error as `e_pk = Decompress(b')-(A·s+e)`, the decryption noise contains `e_pk·r`. Section 2.2's correctness derivation substitutes `b·r` as though no public-key compression occurred, and its Gaussian DFR formula includes `e·r`, `s·e1`, and ciphertext-rounding terms but omits `e_pk·r`. The source performs the same compression/decompression (`KEM_Cheetah.c:96,123`).

Liu estimates corrected log2 failure rates of about −77.85, −51.54, −115.07, and −198.96, versus the submission's −129, −176, −189, and −243. Those **numerical** estimates have not been independently reproduced or measured against the full KEM here. The confirmed result is the missing nonzero term, which invalidates the quoted derivation; this report does not claim a practical decapsulation attack.

### Reproducing

```sh
python3 kem-09/reproduce_pk_compression_noise.py
```

The script exactly enumerates the source's one-coefficient public-key rounding error for each `db` and confirms a nonzero `e_pk·r` variance under the submission's independent-coefficient surrogate. It does not compute a failure tail or validate Liu's four exponents.
