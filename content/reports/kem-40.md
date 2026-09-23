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

Severity: Medium
Status: Probable
Layer: Side-channel
Affected: Reference decapsulation, all three parameter sets
Discovery: Trivial
Exploitation: Local cache/address-trace leak of an internal decryption value; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

During decapsulation, `yy_decrypt_ciphertext` computes `hamming` and `overflow` from the ciphertext multiplied by the private key (`kem.c:181-220`). It then reads the private inverse polynomial at `sk->finvint[(i-overflow+h)%h]` for each `i` (`kem.c:224`). The address pattern rotates with the secret-derived `overflow`, creating a cache/address side channel even though the surrounding loops have fixed bounds. No full secret-key or shared-secret recovery is claimed; see `constant_time.md`.

### Reproducing

The same source path occurs in `yuanyang-512`, `yuanyang-1024`, and `yuanyang-2048` reference `kem.c` files. Inspect lines 181–224 and the call from `yy_decapsulate_API` at line 249. This is a source/dataflow witness; a measured cache attack remains open.
