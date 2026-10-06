<!-- synchronized report: kem-40/report.md -->
Candidate: YuanYang.KEM
Family: Lattice (NTRU)
Archive: [YuanYang.KEM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/YuanYang.KEM.zip) (SHA-256: `fe1bf3d78272bb79048e7d456819160324c6140206798cb77a22c2babcfdcf4a`)

## kem-40-1: Encryption discards the specified error polynomial

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Trivial
Exploitation: Security-proof gap; no complete attack demonstrated
Credit: Yijian Liu (archive sender `Yijian_Liu`)
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FXRFQBH243BPG4XMEBKRPWCAQVGINRWF/)

Algorithm 3 specifies `c_bar = h*s + e + m*p^-1 mod q`, and the IND-CPA proof invokes decisional Ring-LWE for `(h, h*s+e)`. Every submitted `yy_encrypt` samples both `s` and `e`, but computes the ciphertext from `h*s` and the encoded message without ever reading `e` again.

This confirms Yijian Liu's [mailing-list report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FXRFQBH243BPG4XMEBKRPWCAQVGINRWF/). The shipped ciphertext distribution is not the distribution analyzed by the proof or the failure calculation. Omitting `e` is not by itself a demonstrated message-recovery attack—classical NTRU encryption can use a single ephemeral short polynomial—but the submitted implementation cannot claim the stated Ring-LWE reduction without a new analysis.

### Reproducing

```sh
python3 kem-40/reproduce_unused_error.py
```

The static witness checks all three independent implementation copies and fails unless `e` is sampled and then absent from the remainder of `yy_encrypt`.

## kem-40-2: Decapsulation addresses a private array with a secret-derived index

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference decapsulation, all three parameter sets
Discovery: Trivial
Exploitation: Local cache/address-trace leak of an internal decryption value; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

During decapsulation, `yy_decrypt_ciphertext` computes `hamming` and `overflow` from the ciphertext multiplied by the private key (`kem.c:181-220`). It then reads the private inverse polynomial at `sk->finvint[(i-overflow+h)%h]` for each `i` (`kem.c:224`). The address pattern rotates with the secret-derived `overflow`, creating a cache/address side channel even though the surrounding loops have fixed bounds. No full secret-key or shared-secret recovery is claimed; see `constant_time.md`.

Constant-time fix (easy, hence Low): read `finvint` at fixed addresses and apply the rotation by `overflow` with a constant-time barrel shifter (log2 h masked conditional rotations). This multiplies the cost of that one h-coefficient loop by about log2 h, which is small next to the polynomial multiplication in decryption.

### Reproducing

The same source path occurs in `yuanyang-512`, `yuanyang-1024`, and `yuanyang-2048` reference `kem.c` files. Inspect lines 181–224 and the call from `yy_decapsulate_API` at line 249. This is a source/dataflow witness; a measured cache attack remains open.

## kem-40-3: YuanYang resets the external DRBG for deterministic encryption

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: yuanyang-512, -1024 and -2048 reference implementations
Discovery: Trivial
Exploitation: Encapsulation and FO re-encryption agree only for the particular external RBG stream; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

`yy_encrypt` resets a local external `DRNG_ctx` from its deterministic encryption seed, then draws the blinding message and error polynomials (`kem.c:105–122`). Both encapsulation and decapsulation call `yy_encode_message`, which invokes this path (`:138–143,165,260`). Replacing the RBG changes the re-encryption result and makes honest ciphertexts fail validation.

The three frozen implementations work with their bundled `drng.c`. The Low defect is using a replaceable RBG interface as the scheme's deterministic encryption PRG.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-40-3
```

## kem-40-4: Dead even-rounding corrections invalidate the submitted failure estimates

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: YuanYang.KEM-1024 and -2048, reference and optimized implementations; -512 is the odd-parameter control
Discovery: Moderate
Exploitation: Model lower bounds of about 2^-193.47 and 2^-315.78 miss the 256- and 512-bit targets by 62.5 and 196.2 bits; no failure oracle or key recovery demonstrated
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-04
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PE673XVURNT46OQUVSIFJNEXWJFSJLLX/)

The specification says that Decrypt's line 3 removes the low-part message bias and the even-`k` compression bias before the centered lift (Algorithm 4, physical p. 10), and §5.5 (physical pp. 17–18) models centered compression noise. In all submitted 1024/2048 implementations, however, `yy_kem_expand_private_key` writes the extra even-parameter term behind an impossible comparison, so the expanded table is only `floor(f·sum_{i<d/4} X^i/2)` (`kem.c:279–297`). Encryption also uses the even-scale offset `sc/2+1` rather than nearest rounding (`kem.c:127`).

Under the specification's Gaussian model, the post's exact-convolution calculation gives adjacent-pair lower bounds near `2^-193.47` and `2^-315.78`, respectively. These miss the 256-/512-bit targets by 62.5 and 196.2 bits, and exceed the submitted `2^-270.2` and `2^-531.5` estimates by 76.7 and 215.7 bits. The post also reports direct code replay of the bias and large simulations of the rare-key distribution. The specification is self-consistent; the confirmed defect is that the implementation's operator-precedence error and rounding offset do not implement it. No concrete decapsulation failure, oracle, or key recovery was executed, so the consequence remains Medium rather than a demonstrated CCA attack.

### Reproducing

```sh
python3 kem-40/reproduce_bias_correction.py
```

The local certificate verifies both defective expressions in all six reference and optimized source trees and checks that only the even-parameter 1024/2048 sets are affected. The numerical failure bounds are those reported from the specification's model and are not independently recomputed by this short certificate.

## kem-40-5: Truncated encryption seed permits a 2^440 challenge-key distinguisher at the 512-bit level

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: YuanYang.KEM-2048 reference and optimized implementations; the 512/1024 sets are controls
Discovery: Moderate
Exploitation: Offline IND-CCA real-or-random challenge-key distinction in at most 2^440 encryption-seed-prefix trials; no exhaustive run performed
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06

The specification gives Encrypt a 512-bit seed and message (Algorithm 3, physical p. 10) and targets 512-bit classical security (§3 and Table 3). In the submitted `yuanyang-2048`, encapsulation derives its encryption seed from the message and public-key hash (`kem.c:157–165`), but `yy_encrypt` supplies only its first 55 bytes to the local SM3-DRNG (`kem.c:105–119`, `drng.h:15`). The DRBG itself accepts a longer seed (`drng.c:244–252`); the truncation is at this caller. Thus the first 512 DRBG output bits, the blinding message `B`, depend on at most 440 bits. The ciphertext ends with `u = msg XOR H(B || 44)` (`kem.c:129–145`), and the shared key is `H(msg || ct || 43)` (`kem.c:166–170`). The relevant optimized files are byte-identical.

Given one IND-CCA challenge `(ct, K*)`, enumerate the 2^440 possible 55-byte encryption-seed prefixes. For each, initialize the local DRBG, generate its first 512 output bits `B`, recover a candidate `msg = u XOR H(B || 44)`, and compare `H(msg || ct || 43)` with `K*`. The real key always matches; for a uniform random 512-bit challenge key, the union-bound false-match probability is at most 2^-72. This is a single-ciphertext attack on the submitted implementation, not a multi-target loss, and it still works with ideal replacement hashes of the same output lengths. The 440-bit work bound is theoretical and below the required 512-bit level even after ordinary per-trial hash costs; no feasible key recovery is claimed.

### Reproducing

```sh
python3 kem-40/reproduce_truncated_encryption_seed.py
```

The source certificate verifies the seed cap, 55-byte DRBG state, first-output dependency, ciphertext tail and final key derivation. It checks the 512/1024 sets as unaffected controls; it does not enumerate 2^440 states.
