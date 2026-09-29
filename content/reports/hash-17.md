<!-- synchronized report: hash-17/report.md -->
Candidate: MasterCube
Family: Symmetric (sponge, AndRX permutation)
Archive: [MasterCube.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/MasterCube.zip) (SHA-256: `1f9773b8ece90152a6a9adc632a7112c9afc670a5d28b7f1e9ac111e5eea8f13`)

## hash-17-1: Trivial collisions at every rate boundary

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [MasterCube team's confirmation and erratum](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/IG2TAQNA7YHL4JLOOWBTJGKBVVVESWZK/)

The following collision was verified against MasterCube-512:

- Input 1: 958 one bits, encoded in 120 bytes of `ff` with length 958 bits
- Input 2: 959 one bits, encoded in the same buffer with length 959 bits

Both produce:

`847a067d6eb9078d5c3ce3e3f08fbfd3a1488eb6e89909144db1a76d5fcb9a097fef21b4927bb6fe0a1bb2769ef0f249734550c1e8acfa0023a1281d12131bf6`

The implementation attempts to apply `pad10*1` in a single rate block. When the message length is `r-1 mod r`, only one bit remains. The opening and closing delimiter bits are ORed into the same position instead of emitting the additional block required by the specification.

Consequently, for any prefix `P` of length `r-2 mod r`, the implementation gives `H(P) = H(P || 1)`. The same defect was reproduced at 702/703 bits for MasterCube-768 and 446/447 bits for MasterCube-1024. It directly violates the claimed 256-, 384-, and 512-bit collision strengths and is an implementation error rather than an attack on the specified permutation.

The MasterCube team subsequently confirmed the one-bit padding error. The archived Round 1 implementation assessed here remains affected.

### Proposed fixes

The [MasterCube team's response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/IG2TAQNA7YHL4JLOOWBTJGKBVVVESWZK/) proposes emitting an additional block when only one bit remains for `10*1` padding and adding that case to the specification. This section records the proposal without evaluating it.

### Reproducing

Build the candidate and the reproducer, then run:

```sh
make -C api harness && make -C tools && make -C hash-17
tools/ngcc_attack hash-collide-rate hash-17/lib/libMasterCube-512.so 959
```

`tools/reproduce.sh` runs this together with the other supported runtime
witnesses and their controls. See `tools/README.md`.

## hash-17-2: The specified and implemented inverse rounds do not invert the forward round

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specification and reference/optimized implementations, all parameter sets
Discovery: Moderate
Exploitation: Construction and conformance failure; no collision demonstrated
Credit: ISCAS (archive sender `Cryptanalysts001`)
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/2XVZUBVVMVXYKMSOBJOKY2IFHFMQUNEK/)
Follow-up source: [MasterCube team's confirmation and erratum](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/IG2TAQNA7YHL4JLOOWBTJGKBVVVESWZK/)

As [reported on the CryptHash mailing list](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/2XVZUBVVMVXYKMSOBJOKY2IFHFMQUNEK/), the inverse in Algorithm 2 does not invert the published forward round, and the implementation differs from Algorithm 2 but still fails the inverse identity. In the code, the nonlinear calls are already reversed correctly, yet an extra exchange of the two slices remains; additionally, the forward `MixColumns` is reused although its inverse is `J MixColumns J`, where `J` exchanges the slices.

This matters to the complete hash: MasterCube's `Cube-f` transformation XORs the forward branch with a branch explicitly designed as its inverse, while the reference and optimized hashing paths execute the defective branch. Correcting the two operations changes the transformation and resulting digests. The finding invalidates conformance and the archived inverse-branch description, but it does not establish noninjectivity of the forward permutation or by itself give a hash collision or preimage attack.

The MasterCube team confirmed that the old Algorithm 2 was not a genuine inverse because its pseudocode omitted the slice swap.

### Proposed fixes

The [MasterCube team's response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/IG2TAQNA7YHL4JLOOWBTJGKBVVVESWZK/) proposes adding the missing slice swap to Algorithm 2 and explaining how to reuse `MixColumns` for the inverse. This section records the proposal without evaluating the team's further claims about its effect on proofs, design rationale, or performance.

### Reproducing

The witness uses the submitted MasterCube-512 round functions. On the mailing-list state `(left,right)=(1,0)`, a forward round followed by the submitted inverse returns `(0,1)`; the corrected inverse returns the input exactly.

```sh
cc -O2 -std=c99 -Ihash-17/MasterCube/Implementations/Reference_Implementation/MasterCube-512 \
  hash-17/reproduce_inverse.c -o /tmp/mastercube-inverse
/tmp/mastercube-inverse
```

Expected output:

```text
CONFIRMED: forward round followed by submitted inverse swaps the slices
CONTROL: corrected inverse recovers the input exactly
```
