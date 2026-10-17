<!-- synchronized report: kex-09/report.md -->
Candidate: TriQ-KEX
Family: Code-based authenticated key exchange
Archive: [TriQ-KEX.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/TriQ-KEX.zip) (SHA-256: `dde9bf3e8d75fc3df53bcbcacaba4faed39272b8ef2f1ac199ae0128d327b505`)

## kex-09-1: Decapsulation re-expands its secret key with a variable-length sampler

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: TriQ-KEX reference implementations (128, 256, 384, 512)
Discovery: Trivial
Exploitation: Secret-seed-dependent control flow and work on each decapsulation; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

`crypto_kem_dec()` passes the persistent secret PKE seed to `triq_pke_decrypt()`, which calls `triq_dk_pke_from_string()` on every decapsulation. That function expands the seed through `vect_sample_fixed_weight1()`. Its support sampler repeats on rejected or duplicate secret-derived positions (`vector.c:69-90`), and refills an XOF buffer when the extra draws cross its boundary. Thus otherwise identical decapsulation calls perform a secret-key-dependent number of loop iterations and XOF calls. The four reference variants share the same sampler. This is a secret-dependent timing/control-flow leak, not an established full-key attack; see `constant_time.md` for the data-flow trace.

Constant-time fix (moderate, hence Medium): store the expanded support in the private key instead of re-deriving it on every decapsulation, which changes the key format and storage, or sample it with a fixed number of draws and constant-time duplicate handling. Both are well-known techniques with moderate cost.

### Reproducing

From the repository root, compile the witness against the submitted TriQ-128 source:

```sh
ct_dir=$(mktemp -d)
ref=kex-09/TriQ-KEX/Implementations/Reference_Implementation/TriQ-KEX-128
cc -std=c99 -O3 -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -I "$ref/src/common" -I "$ref/src/common/triq-128" \
  -I "$ref/src/ref" -I "$ref/src/ref/triq-128" -I "$ref" \
  -o "$ct_dir/repro" kex-09/reproduce_ct_sampler.c \
  "$ref/src/common/symmetric.c" "$ref/auxfunc.c"
"$ct_dir/repro"
```

The witness counts XOF fetch calls in the unmodified reference sampler. It prints `CONFIRMED` after finding two secret seeds (first byte 0 and 11 in this build) that require different call counts. An extra fetch performs another XOF invocation and allocation, making the paths observably different without a statistical timing test.

## kex-09-2: FO re-encryption leaks the decrypted message through sampler timing

Severity: Medium
Status: Lead
Layer: Side-channel
Affected: TriQ-KEX reference and optimized implementations, 128/256/384/512; timing measured on TriQ-KEX-128's internal KEM
Discovery: Moderate
Exploitation: Chosen-ciphertext timing classifier; full key recovery not demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 and Anthropic Claude Opus 5.5 assistance
Date: 2026-09-30
Original source: [PKC Forum post and verification package](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FJSWIK5YXD6SNYN22H6GT3XE6A5RRKN4/)

The KEX's internal KEM decapsulation decrypts `m_prime`, derives `theta_prime` from it, and re-encrypts before comparing the ciphertext (`src/common/kem.c:156–171`). Re-encryption calls the bounded-density sampler twice (`src/ref/triq_pke.c:96–98`). That sampler exits as soon as a candidate passes its density test, so its iteration count depends on `theta_prime` and hence on the secret-dependent decrypted message (`src/ref/vector.c:244–255`); the optimized trees contain the same early exit. The masked final validity selection does not hide this earlier work. This operational dataflow contradicts the specification's statement that the bounded-density condition is public and independent of secret data (§III-B, p. 9).

The unauthenticated `ct_a` is decapsulated with the long-term KEX secret before peer authentication (`KEX_AlgorithmInstance.c:404`), so an active party can reach this path. The reporters measured a 7.9% probability that a full internal-KEM re-encryption needs at least one extra draw across its two sampler calls, corresponding to about 4.1% per call under the same model. Its two timing classes differed by 37,227 cycles: one averaged 10,220,477 cycles and the one-extra-rejection class 10,257,704 cycles (`z` about 4.4); a quieter-host run reached `z=5.6`. A separate microbenchmark measured one extra sampler iteration at roughly 15,674 cycles, so the figures are not measurements of the full KEX. This is the re-encryption leakage mechanism used by the published [Don't Reject This attack](https://eprint.iacr.org/2021/1485) on related code-based KEMs. A TriQ-specific classifier is demonstrated, but a complete secret-key recovery is still in progress.

Constant-time fix (moderate, hence Medium): run a fixed, message-independent number of sampler candidates and use masks to select the first acceptable one. The original analysis estimates about 78% extra sampler work for a two-candidate schedule; that performance estimate and its residual failure probability have not been independently validated.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/FJSWIK5YXD6SNYN22H6GT3XE6A5RRKN4/) proposes running exactly `N_max` sampler iterations with masked selection, or using another fixed message-independent schedule. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kex-09/reproduce_reencrypt_sampler.py
```

The compact witness checks the decrypted-message-to-sampler dataflow and early exit in all four archived trees. It deliberately does not claim to reproduce a stable timing classifier or key recovery on every host.

## kex-09-3: Role labels instead of identities permit a copied-key unknown-key-share

Severity: Medium
Status: Confirmed
Layer: Design
Affected: TriQ-KEX-128, TriQ-KEX-256, TriQ-KEX-384 and TriQ-KEX-512 when certification permits duplicate public keys
Discovery: Trivial
Exploitation: One duplicate-key registration and one relayed honest exchange against the unmodified libraries; no break of the distinct-key formal model
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

TriQ-KEX instantiates the FSXY transformation and targets CK+ security (specification physical pp. 1 and 3). In FSXY, the session transcript begins with the initiator and responder party identities. TriQ instead defines `U_A` and `U_B` as "role labels for the initiator and responder" (p. 4), sets `ST = (U_A, U_B, ek_A, ek_B, CT_A, ek_T, CT_B, CT_T)` (p. 8), and implements the labels as the fixed four-byte strings `ID_A` and `ID_B` (p. 13). Every reference and optimized wrapper does the same: `KEX_AlgorithmInstance.c:62–63` defines the constants, and the `APPEND_ST` block (lines 271–279 at TriQ-KEX-128) hashes them ahead of the key and ciphertext bytes. A party's identity therefore enters the session key only through its public-key bytes.

If Eve obtains a certificate for Bob's key under her own name, Alice can initiate to "Eve" and Eve can relay both messages unchanged to Bob, who believes his peer is Alice. Both parties compute the same `ST` and the same key, while Alice records the peer as Eve and Bob records the peer as Alice. The mirror attack also works: Eve registers Alice's key, and Bob believes he is talking to Eve. Revealing one session's key gives the other session's key, even though the sessions do not match.

The attack requires a certificate for a duplicated key. A deployment that rejects duplicate registrations, or that binds certified identities into `ST`, is not affected by this particular attack.

### Reproducing

```sh
make -C kex-09
python3 kex-09/reproduce_copied_key_uks.py
```

On all four prebuilt libraries and with two seeds each, the script runs both copied-key directions. It requires the role labels to appear on the wire and the two keys to be equal. Its controls require an honest exchange to agree and an independently generated key for Eve to produce different keys. When the sources are present, it also checks the `ST` layout. It runs in about 8 seconds.
