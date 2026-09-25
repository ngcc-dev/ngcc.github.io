<!-- synchronized report: kem-13/report.md -->
Candidate: DKEM (Ding Key Encapsulation)
Family: Lattice (Module-LWE)
Archive: [DKEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DKEM.zip) (SHA-256: `862f40ba424253bae7fadbc9c2f54a568b77e0f97fba4728c5fd1e4e826dddc7`)

## kem-13-1: DKEM's rejection key does not bind the full ciphertext

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All DKEM parameter sets and submitted implementation families
Discovery: Trivial
Exploitation: Rejected ciphertexts sharing `c2` share a key; no IND-CCA or shared-secret recovery attack shown
Credit: Jieyu Zheng (GitHub @zhengjieyu)
Date: 2026-09-25
Original source: [ngcc-harness issue #16](https://github.com/ngcc-dev/ngcc-harness/issues/16)

Specification Algorithm 16 derives the rejection key as `KDF(rej || c2)`, omitting the `c1` component of `ct = c1 || c2`. The twelve submitted `dkecca.c` copies do the same (`dkecca.c:109–111`). Thus distinct rejected ciphertexts with the same `c2` return the same key, violating full-ciphertext key binding. With access to decapsulation outputs, comparing a ciphertext's key to that of a changed-`c1` ciphertext also distinguishes acceptance from rejection, contrary to the specification's §5.3 claim that implicit rejection provides no validity signal. This does **not** establish an IND-CCA break or a way to recover an honest party's secret key or session key; the submitted IND-CCA proof explicitly models this `c2`-only rejection derivation.

### Reproducing

```sh
make -C api harness
make -C kem-13
python3 kem-13/reproduce_rejection_binding.py \
  kem-13/lib/libDKEM-128.so kem-13/lib/libDKEM-256.so \
  kem-13/lib/libDKEM-512.so
```

For each parameter set, the witness checks an honest encapsulation, two distinct rejected `c1` values with the same `c2` and identical decapsulation keys, and a changed-`c2` control with a different key. It exercises the archived reference implementation; the identical rejection derivation in optimized and additional sources was checked statically.

## kem-13-2: Malicious public key defeats DKEM's contributory key derivation

Severity: Medium
Status: Confirmed
Layer: Design
Affected: DKEM-128, DKEM-256, and DKEM-512
Discovery: Trivial
Exploitation: Fresh encapsulations to a malicious public key produce a repeated, predictable key; protocol impact depends on how the key is used
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

The specification's §3 says DKEM is “contributory by construction” because both parties affect the reconciled secret. This claim fails for an attacker-supplied public key whose polynomial vector is zero. In Algorithm 11, the sender's product with that vector vanishes; the remaining doubled, small error produces a zero reconciliation signal and an all-zero raw shared secret. Algorithm 14 and `dkecca.c` then derive the final key from that raw secret alone, so fresh sender coins and distinct ciphertexts all yield the same `KDF` output. The ciphertext's `c2` also exposes the coins because it XORs them with the zero raw secret. This holds for each submitted parameter set and does not depend on weaknesses of the placeholder hash functions.

The witness gives 64 distinct ciphertexts but one shared key across 64 encapsulations for each parameter set, versus 64 distinct keys with an honestly generated public key. For DKEM-128 and DKEM-256 the repeated key is exactly `sm3hash(256, 0^32)`. This is a malicious-public-key contributiveness and key-binding failure; it does not establish an IND-CCA break for honestly generated keys or show that a recipient accepts these ciphertexts under an honestly generated secret key. Including fresh sender input in the final key derivation would prevent this particular repeated-key outcome; any broader public-key or ciphertext binding claim needs its own analysis.

### Reproducing

```sh
make -C api harness
make -C kem-13
python3 kem-13/reproduce_malicious_key.py \
  kem-13/lib/libDKEM-128.so kem-13/lib/libDKEM-256.so \
  kem-13/lib/libDKEM-512.so
```

For each parameter set, the witness encapsulates 64 times to an honestly generated public key (control: 64 distinct keys) and 64 times to the same key with its polynomial vector zeroed and `rho` kept. It checks distinct ciphertexts and distinct `c2` values but a single key, and for 32-byte keys that the key equals `sm3hash(256, 0^32)`. The source-level trace, identical in all three `Reference_Implementation/DKEM-*` instances, is Algorithm 11's zero public vector, `dkecpa.c:174–186` (the sender's reconciled secret), `dke_utils.c:97–105,172–176` (signal and raw-secret extraction), and `dkecca.c:65–76` (the final key and `c2`).
