<!-- synchronized report: sign-07/report.md -->
Candidate: CS
Family: Lattice (Module-LWE, Fiat-Shamir)
Archive: [CS.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CS.zip) (SHA-256: `c790d31cd4a288990f3d692381ed721a06641938a02dfc2e0435b7d323475cef`)

## sign-07-1: Trivial signature malleability violates SUF-CMA

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The signature contains a fixed-size rANS encoding area and an encoded byte count. `sigDecode` consumes only the indicated meaningful bytes and does not require the unused tail to be zero or otherwise canonical.

Changing the last unused signature byte produces a distinct signature that continues to verify for the same public key and message. This transformation needs neither the secret key nor a signing query beyond the original valid signature.

The result is not a new-message forgery and therefore does not alone violate EUF-CMA. It directly violates the submitted strong-unforgeability claim, which forbids producing a second accepted signature for an already signed message.

Verification must enforce a unique encoding, including the complete fixed-size tail.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C sign-07
tools/ngcc_attack sig-malleable sign-07/lib/libCS-128.so
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## sign-07-2: Verifier challenge-sign blindness enables universal forgery

Severity: High
Status: Confirmed
Layer: Design
Affected: CS-128, CS-256, and CS-512
Discovery: Non-trivial
Exploitation: Approximately 2^108.08, 2^212.46, and 2^394.18 hash trials, respectively
Credit: Kris Kwiatkowski <contact@amongbytes.com>
Date: 2026-09-21
Original source: [ngcc-harness PR #1](https://github.com/ngcc-dev/ngcc-harness/pull/1)

CS samples a weight-`tau` challenge over `{0,+1,-1}` and credits all `tau` sign bits in its challenge-entropy calculation. In both specification Algorithm 12 and `CS_Verify`, however, the challenge reaches verification only through parity: the `-q*c` term is identical for `+1` and `-1` modulo `2q`, and the other hash input retains only `LSB(z0-c)`. Verification therefore sees the challenge support but not its signs.

The verifier also imposes no independent weight or norm bound on the hint. For any chosen support, an attacker can set `z0=z1=0` and choose an encodable hint so that every norm and reconstruction check passes. Grinding the free hint until the hash selects that support costs `binomial(n,tau)`, rather than the `binomial(n,tau)*2^tau` challenge space used in Table 3. Independently recomputed costs are 108.08, 212.46, and 394.18 bits, below every claimed classical level; generic quantum search halves those exponents.

The complete submitted-size grinds were not executed. The reproducer proves the free-transcript construction at every submitted parameter set and runs the same attack to completion on a scaled CS-128 instance with `tau` reduced from 23 to 3. Compensating `B0`, `B1`, `B2`, and `M0` adjustments preserve the `z0` and `z1` bounds and tighten the `z2'` bound from 2812 to 2521. The submitted verifier compiled with those scaled parameters accepted the forged signature without a signing query or secret key. Binding the challenge signs into a verifier-visible equation and bounding the hint are both necessary repairs.

### Reproducing

```sh
make -C sign-07 libs exploit
sign-07/forgery_CS-128-scaled-tau3 \
  sign-07/lib/libCS-128-scaled-tau3.so --threads 4 --verbose
sign-07/forgery_CS-128 sign-07/lib/libCS-128.so \
  --control --threads 4 --trials 200000 --verbose
sign-07/forgery_CS-256 sign-07/lib/libCS-256.so \
  --control --threads 4 --trials 200000 --verbose
sign-07/forgery_CS-512 sign-07/lib/libCS-512.so \
  --control --threads 4 --trials 200000 --verbose
```

## sign-07-3: Compressed signatures may leak the CS-128 signing key

Severity: High
Status: Lead
Layer: Design
Affected: CS-128 full compressed scheme; higher sets not evaluated
Discovery: Non-trivial
Exploitation: Reporter claims recovery from 2^27 signatures; not independently replayed
Credit: Yijian Liu (on behalf of Xianhui Lu; with AI assistance)
Date: 2026-09-24
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PNQJ4PBNVDPNY624PDPCOO7ZL2GXIP6H/)

In the full compressed scheme, §3.4 (Correctness) derives the verifier-visible relation `z2' = z2 - c_r·b_0 + (-LowBits_h(w,α)+LSB(w))/2 (mod ±q)`, where `b_0` is the secret low part of the public-key relation and `c_r` aggregates hidden bimodal signing signs. Liu reports estimating `E[c_r | z0,c]` from public signature fields, then using its correlation with `z2'` to recover all coefficients of `b_0`; a second cross moment reportedly recovers `s1`, from which the remaining short key follows. The cited experiment used `2^27` CS-128 signatures and reported exact 768-coefficient recovery after normalization.

The `c_r·b_0` term and public reconstruction are verified in specification Algorithm 11/12 and reference `cs.c`. The statistical estimator, sample cost, and claimed full key recovery are **not** independently reproduced: the post supplies no attack code or public transcripts. This is a high-priority lead, not a confirmed key-recovery break. It is separate from `sign-07-2`'s challenge-sign-blind forgery.

### Reproducing

Compare §3.4's correctness identity with Algorithm 11, Algorithm 12, and `CS_Sign`/`CS_Verify` in the archived CS-128 reference source. This checks the secret-dependent public relation only; a full witness requires the reporter's 2^27-signature estimator or an independent equivalent.
