<!-- synchronized report: kex-07/report.md -->
Candidate: NEV-AKE
Family: Lattice (NTRU/Ring-LWE AKE)
Archive: [NEV-AKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NEV-AKE.zip) (SHA-256: `da75005b4060167f25125cbd1a769ed872c8b6fcb770fe0827a599e44536e8e6`)

## kex-07-1: Both party identities are hard-wired to zero

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Uniform-API reference wrappers, all nine parameter sets
Discovery: Trivial
Exploitation: One copied or byte-distinct re-encoded key registration and one relayed exchange give an unknown-key-share on all nine sets; no key recovery
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Every submitted `kat_test/KEX_AlgorithmInstance.c` allocates the initiator and responder identities as all-zero `SEED_BYTES` arrays. The wrappers pass those constants into responder processing and initiator key derivation for all nine profiles.

The official `KEX_AlgorithmInstance.h` API exposes no identity argument, so the wrapper had no channel through which an application could supply the modeled identities. A sound integration could instead derive stable identities from the parties' public keys; hard-wiring both to zero removes the binding entirely.

The core `ake.c` code hashes both identities into the session-key computations, and the specification's CK+ model distinguishes the session holder and peer identities `i` and `j`. The wrapper therefore collapses every deployment and every pair of parties onto one fixed identity pair instead of instantiating the protocol's modeled identity binding.

This is a confirmed integration security defect. Extended on 2026-10-17: a complete unknown-key-share now runs through the fixed API on all nine sets. GC-AKE derives `K = H(m_i, m_j, K~, i, j, M, M')` (specification Fig. 5, physical p. 19, and Algorithms 3–4, p. 20; `ake.c:29–48`). Here `M = (c_j, pk~)` and `M' = (c_i, ct~)` carry only ciphertexts and the ephemeral key. The transcript therefore does not contain the static public keys, which corrects the earlier statement that it did, and the zero identities are the only explicit peer binding. Suppose Eve registers a copy of Alice's public key, Alice initiates to Bob, and Eve tells Bob that the initiator is Eve. Bob encrypts `m_i` under the copied key, Alice decrypts it consistently, and both parties hash identical inputs. They hold the same key while Alice's peer is Bob and Bob's peer is Eve, which violates the holder and peer agreement of matching sessions (Definition 9, p. 13). With distinct identities in `i` and `j`, the two keys would differ.

The copied key does not have to be byte-identical, because the public-key decoders do not range-check coefficients. At q = 1409, `decode16` (`pack.c:140–141`) decodes `(x1 + 1409)·1409 + x0 < 2^21` as `x1 + 1409 ≡ x1`. At q = 769, the trailing `n mod 5` coefficients are read raw from 10 bits (`pack.c:329–350`), so `x + 769 < 1024` also decodes to `x`. Every tested key at q = 1409 and about 50–80% of keys at q = 769 have such a byte-distinct alias, and the alias gives the same unknown-key-share. A certification authority that rejects only byte-identical duplicates therefore does not prevent the attack. The attack still needs a certificate on a copied or re-encoded key. It recovers no key, so the Medium rating is unchanged.

### Reproducing

The zero-initialized `idi` and `idj` arrays are at lines 105–106 and 165–166
of `NEV-AKE-C1/kat_test/KEX_AlgorithmInstance.c`; the other eight reference
wrappers have the same assignments.

```sh
make -C kex-07
python3 kex-07/reproduce_uks.py
```

The script checks those wrapper lines and confirms that `ake_hash_h` has no
public-key input. It then runs 20 seeded trials per set on all nine prebuilt
libraries. Each trial runs a copied-key and a byte-distinct alias
unknown-key-share and requires equal keys. Its controls require an honest
exchange to agree, and an independently generated key or a non-congruent
re-encoding of the same coefficient to give different keys. It runs in about
a second; pass a larger trial count as the first argument.

## kex-07-2: Short responder messages reach fixed-size decryption without a length check

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All nine submitted NEV-AKE reference uniform-API wrappers
Discovery: Trivial
Exploitation: A short peer-supplied responder message can cause an out-of-bounds read; no secret disclosure or protocol break demonstrated
Credit: fa1c4 (University of Science and Technology of China)
Date: 2026-10-20
Original source: [NGCC harness issue 33](https://github.com/ngcc-dev/ngcc-harness/issues/33)

`kex_derive_ss_a` discards `mb_len_bytes` and passes `mb` to `ake_der_init` in all nine wrappers (`kat_test/KEX_AlgorithmInstance.c:158–173` in C1). The core splits that pointer into a fixed-size PKE ciphertext and KEM ciphertext before decrypting both (`ake.c:177–207`). A one-byte responder buffer therefore does not constrain either read. The reporter observed an AddressSanitizer error. Our source check confirms the unchecked path and scope, not the precise runtime crash or any disclosure.

### Reproducing

```sh
python3 kex-07/reproduce_short_message.py
```

The certificate traces the length discard and fixed-size decryption in all nine submitted trees. It does not execute a malformed exchange.
