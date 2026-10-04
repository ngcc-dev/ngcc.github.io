<!-- synchronized report: sign-04/report.md -->
Candidate: CEDRUS-alpha
Family: Hash-based
Archive: [cedrus-alpha.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/cedrus-%CE%B1.zip) (SHA-256: `b90559ca94bda0130420f91fa52eeb242063a57188c766037c1b234ec3af563b`)

## sign-04-1: The 160-bit WOTS implementation authenticates only 128 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: CEDRUSALPHA-160s and CEDRUSALPHA-160f, reference and optimized implementations
Discovery: Trivial
Exploitation: About 2^128 work to replace an authenticated lower-layer root, below the 160-bit claim
Credit: shiyuan (NGCC PKC Forum sender)
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/S5GGRLD7YZQQRH2VPPYET2GWYTHFWKXR/)

Shiyuan reported the defect in the [NGCC PKC Forum](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/S5GGRLD7YZQQRH2VPPYET2GWYTHFWKXR/). The specification converts the complete `n`-byte WOTS message to an integer. In both 160-bit implementations, however, `WOTS_UINT_WORDS` is `SPX_N/8 = 2`, and `chain_lengths()` loads only two eight-byte words. Bytes 16 through 19 of every FORC or child-XMSS root are ignored by WOTS signing and verification.

The implementation therefore authenticates only a 128-bit prefix at these layers, contradicting the stated 160-bit classical strength. An attacker can replace an authenticated lower-layer result by grinding candidate subtree roots until that prefix matches, at about `2^128` work, and then use the replacement subtree for a fresh message. The forum post's separate `2^64` collision figure does not by itself give a `2^64` signature forgery. The `2^128` full-scheme path is nevertheless a concrete attack bound below the 160-bit claim, so the finding is Critical even though the full-size computation has not been run.

### Reproducing

```sh
make -C sign-04 exploit
```

The first control calls the submitted `chain_lengths()` and `wots_pk_from_sig()` on two 20-byte inputs that differ in all trailing 32 bits and obtains identical outputs.

## sign-04-2: FORC chain addresses are truncated to eight bits

Severity: Critical
Status: Probable
Layer: Implementation
Affected: Address aliasing affects all eight reference and optimized sets; the below-target forgery estimate is for CEDRUSALPHA-160f
Discovery: Moderate
Exploitation: With 2^64 signatures, a conservative model estimates about 2^123.3 public target-hash trials for a fresh-message forgery on CEDRUSALPHA-160f
Credit: shiyuan (NGCC PKC Forum sender); 2^64-signature accumulation extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DZLVOKPTO2KZTN76AGZ2SST2T5ZCIUB7/)

Shiyuan reported the defect in the [NGCC PKC Forum](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DZLVOKPTO2KZTN76AGZ2SST2T5ZCIUB7/). The specification assigns a full 32-bit `chainAddr` with domain `0..k*2^a-1`. The implementation writes the value only to address byte 27, so indices congruent modulo 256 generate identical PRF and FORC-chain inputs. The intended `k*2^a` leaf secrets consequently draw from at most 256 distinct values inside a fixed FORC address context.

This invalidates the specification's independence model and aliases leaves both within and across FORC trees. Observations from different complete FORC contexts cannot be pooled, so the forum post's original coupon-collector argument alone did not establish a forgery.

### Follow-up Analysis

Follow-up date: 2026-10-04

Further extension to shiyuan's analysis combines the aliases with repeated-address accumulation. For CEDRUSALPHA-160f, `2^64` signatures distributed over `2^66` complete bottom addresses give mean bucket occupancy `1/4`. Inside one bucket, each disclosed chain node is shared by 14 same-parity FORC coordinates. The attacker advances these nodes to leaf endpoints, retains the coordinate-specific authentication siblings disclosed by the signatures, and publicly hashes known child pairs into further Merkle nodes. It then grinds the public `R` on a fresh message until `H_msg` selects a covered address and digest, and reuses that address's authenticated hypertree suffix.

A deliberately conservative deterministic-seed model performs only the first level of this public Merkle closure. Its Poisson mixture estimates success near `2^-123.28` per target trial, hence about `2^123.28` public `H_msg` trials after `2^64` signatures. Independent native and Python audit implementations agree; unrestricted valid closure estimates about `2^109.64`. Because no exact combinatorial proof or full-size verifier forgery has been produced, the extension is `Probable`, not `Confirmed`.

### Reproducing

```sh
make -C sign-04 exploit
make -C sign-04 reproduce-q64-alias
```

The first command links the submitted address code and SM3 PRF and confirms that indices 0 and 256 produce identical 32-byte addresses and identical secret values. The second runs the conservative `2^64`-signature coverage estimate locally; it does not execute the astronomically large full attack.

## sign-04-3: Specified and implemented hash instantiations are incompatible

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All eight CEDRUSALPHA parameter sets, reference and optimized implementations
Discovery: Trivial
Exploitation: Cross-implementation verification failure; no cryptographic attack demonstrated
Credit: shiyuan (NGCC PKC Forum sender)
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3PASZVC2PGWVNXMF7K5T7S2KZ2RZRZLX/)

Shiyuan documented the mismatch in the [NGCC PKC Forum](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3PASZVC2PGWVNXMF7K5T7S2KZ2RZRZLX/). Specification Section 1.11 pads `PK.seed` to one 64-byte SM3 block, uses the 22-byte compressed address `ADRS^c`, and includes `PK.seed` in `PRF(PK.seed,SK.seed,ADRS)`. The code instead hashes `SPX_N` bytes of `PK.seed` followed by the full 32-byte address, while `prf_addr()` hashes only `SK.seed || ADRS` and receives no public seed.

Thus a conforming implementation of the PDF cannot reproduce the submitted keys, signatures, or verification results. The discrepancy also removes the specified public-seed domain separation from secret-value generation, but no cross-key attack follows from that omission alone.

### Reproducing

```sh
pdftotext -layout sign-04/sign-04-spec.pdf - | grep -A8 'pad the PK.seed'
sed -n '12,30p' sign-04/Implementations/Reference_Implementation/CEDRUSALPHA-160s/hash_sm3.c
sed -n '12,24p' sign-04/Implementations/Reference_Implementation/CEDRUSALPHA-160s/thash_sm3_simple.c
```

## sign-04-4: FORC accumulation gives below-target fresh-message forgeries

Severity: High
Status: Confirmed
Layer: Design
Affected: Specification, all eight parameter sets
Discovery: Moderate
Exploitation: Concrete forgeries use fewer than 2^80 signatures, but the specification-only route remains above the 128-bit target when restricted to 2^64 signatures
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-10-04
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/LKP3BFFIZPFG5R5YTRC6WDLY7XPW7CKK/)

The [pinned analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/6ebb3b4ab00c68d8e72b1c08ba839ed7056dc166/CEDRUS-alpha) validates the following result.

At a repeated complete bottom address, ordinary independently randomized signatures reveal different FORC chain nodes and authentication paths under the same address-specific public key (Algorithms 20–21, physical pp. 35–36; §3.2, p. 45). Forward-compatible nodes from different signatures can be combined coordinate by coordinate, while one retained hypertree suffix authenticates the mixed FORC result. The fresh-message step enumerates the serialized public `R` until `H_msg` selects covered coordinates; the verifier cannot test whether `R` came from `PRF_msg`.

Across all eight sets, optimized constant-success strategies have signing-query means from about `2^71.2` to `2^77.5`, below the evaluation's `2^80` chosen-message ceiling. Attacker public-`H_msg` work is below `2^77.6`, below every claimed level. This is the few-time degradation already parameterized by `q_sig` in §3.2, combined into a concrete forgery. With exactly `2^64` signatures, the best specification-only 160f route instead has mean one-target success about `2^-161.74`, so it does not break the 128-bit target. The design finding is therefore High while the call's `2^64` operational requirement and `2^80` evaluation ceiling remain unresolved. The separate implementation alias extension above does cross the target with `2^64` signatures.

The full specification attack is certificational rather than physically practical. For 160f the fully provisioned table is about `2^79.18` bytes and returned signatures about `2^88.70` bits. The artifact demonstrates scaled fresh-message forgeries, full-parameter FORC splicing with controls, and the absence of a normative per-key cap that excludes the attack.

### Reproducing

```sh
sh sign-04/reproduce_forc_accumulation.sh
```
