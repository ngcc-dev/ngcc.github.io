<!-- synchronized report: kex-02/report.md -->
Candidate: AFS-KEX
Family: Lattice (Module-LWE AKE)
Archive: [AFS-KEX.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/AFS-KEX.zip) (SHA-256: `7d902107b74870e512c84da82c6bfb386633ca864ddc7df2f7b0b183511f983a`)

## kex-02-1: The ephemeral key is generated once as long-term state

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Uniform-API reference wrappers, all three parameter sets
Discovery: Trivial
Exploitation: Trivial after later long-term-key compromise
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

The specification requires fresh AFS ephemeral key material for each session and claims completed-session forward secrecy after later compromise of long-term keys.

The uniform wrapper instead generates `seed_e` and calls the ephemeral key generator inside `kex_init_self`. It embeds the resulting `pk_e/sk_e` into the composite public and secret keys returned as the party's long-term material and stores `seed_e` in the persistent state. Later pass functions reuse that material and never generate a fresh per-session ephemeral key.

This gives a direct completed-session key-recovery attack. A passive attacker records `m1 = ct_B` and the `ct_A` prefix of `m2`. After the session completes, compromise of the two API long-term secret keys exposes `csk_B` and `csk_A` in their first halves. The attacker decapsulates the recorded ciphertexts to recover `K_B` and `K_A`, then computes the public session KDF `XOF(K_B || K_A)`. The result is the exact erased session key. No cryptanalysis or search is required.

Ephemeral AFS keys must be generated for each protocol execution, kept outside long-term key serialization, and erased when the session completes.

### Reproducing

```sh
make -C kex-02 exploit
kex-02/reproduce_pfs_break
kex-02/reproduce_pfs_break_c256
kex-02/reproduce_pfs_break_c512
```

The three drivers complete honest C128, C256, and C512 exchanges, erase both session-state buffers, and recover each session key using only the recorded first two flights and the subsequently compromised API long-term keys. They also check that the true static-key halves alone do not recover the key.

```text
ATTACK kex-pfs-recovery AFS_KEX_C128 CONFIRMED recorded m1/m2 plus later API long-term-key compromise recovered erased session key 1218217aea48c0aee27983653641600a (static-only control differs)
ATTACK kex-pfs-recovery AFS_KEX_C256 CONFIRMED recorded m1/m2 plus later API long-term-key compromise recovered erased session key 40076703841413297c9105f888a439d48f6015ab23774c9539b3ce6e19eeff5e (static-only control differs)
ATTACK kex-pfs-recovery AFS_KEX_C512 CONFIRMED recorded m1/m2 plus later API long-term-key compromise recovered erased session key 12033302a024a20f0d4498daafdc87c3c91d7c9b7479be51280d1cacf286a0b9eab8d3593771c3260f60eaf02cdc4101b3828a0e4d9ebc3bbe742aee77830a1f (static-only control differs)
```

## kex-02-2: Secret-derived decryption coefficients take a sign branch

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: AFS_KEX_C128 reference implementation
Discovery: Trivial
Exploitation: Secret-dependent decapsulation control flow; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The C128 KEM decapsulator decrypts the ciphertext using the secret polynomial, forming `mp = v - skpv*b` (`indcpa.c:354-364`). Message conversion then branches on the sign of each secret-derived centered coefficient (`poly.c:174-193`). This exposes a key- and ciphertext-dependent branch pattern on repeated decapsulation. C256/C512 use different conversion code and are not included in this finding. A KyberSlash-style full-key attack would also need an observable per-coefficient oracle and a chosen-ciphertext recovery argument; neither has been demonstrated here, so this is not rated Critical. See `constant_time.md` for the data-flow trace.

Constant-time fix (easy, hence Low): derive each message bit from the coefficient with arithmetic masks, as in Kyber's `poly_tomsg`, instead of branching on its sign.

### Reproducing

The reference Makefile uses `-O2`. On x86-64 GCC, the following prints the conditional `jns` in the compiled C128 `poly_tomsg` path:

```sh
cd 'kex-02/Implementations and Test_Vectors/Implementations/Reference_Implementation/AFS_KEX_C128'
gcc -O2 -std=c99 -I. -DBWKEM128_INTERNAL_COMPAT -DBWKEM_C128_USE_ICCS_AUXFUNC -S -o - poly.c | sed -n '/bwkem128_poly_tomsg:/,/\.size[[:space:]]*bwkem128_poly_tomsg/p' | grep -E '\bjns\b'
```

The source-level secret dependency is the `indcpa_dec` → `poly_tomsg` chain above; the assembly check confirms that this particular compiler/build does not erase the branch. No timing-based key recovery is claimed.

## kex-02-3: Leaking one in-session encapsulated key permits initiator impersonation

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified pMAKE-BW protocol, all three parameter sets
Discovery: Moderate
Exploitation: Public initiator key plus exposure of one in-session encapsulated key
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6J2L7XPCKMT7VFS4LRE7DSP3BMJRUFEV/)
Follow-up source: [AFS-KEX team's initial statement](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/M4U5QIFRBYA3T6XQ7UCLJV3RDA6J5IIA/), [response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KWCCXWCNCLZBXRLN5GQJCMFUHCFSECXM/), and [further response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5LFINDPHMLECJ6YRWV7QCCMAV7J6JBFL/)

Figure 3 authenticates an initiator by extracting `pk'_A = cpk_A - t_e(seed_A)` and checking `CAVerf(id_A,pk'_A)`. Given Alice's public key, an attacker can choose its own `seed*` and publish `cpk* = pk_A + t_e(seed*)`; extraction then returns Alice's certified public key. If the in-session encapsulated key `K_A` is exposed, the attacker completes the remaining exchange, derives `K_SESSION = PRF(K_A,K_B)`, and is accepted by Bob as Alice. Alice does not participate, and no secret of hers other than the assumed `K_A` exposure is used.

This demonstrates the consequence of exposing an in-session encapsulated key, but it does not contradict the formal proof. Section 9.1 limits `RevealEph` to ephemeral material that can be precomputed offline, assumes encapsulation randomness is erased, and Remark 9.1 discusses retained precomputed keys rather than the in-session `K_A` used here. The same exposure defeats the authentication role of the KEM contribution in many KEM-authenticated AKEs. The confirmed protocol behavior is therefore a Medium model-boundary finding, not a break of AFS-KEX's stated primary game.

The spec-faithful protocol witness built from each submitted reference primitive succeeds in 200 of 200 trials, derives Bob's exact session key, and is rejected in 200 of 200 controls without the `K_A` exposure.

### Follow-up Analysis

The AFS-KEX team states that its intended model excludes arbitrary exposure of in-session ephemeral state and characterizes the protocol as ephemeral KEX. That position is consistent with the report's model-boundary classification; it does not change the reproduced impersonation behavior under the stated exposure.

### Proposed fixes

The original post proposes correcting the public description of which secret authenticates the exchange. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kex-02 reproduce-protocol-findings
```

The pinned wrapper runs the protocol experiment at C128, C256, and C512 and requires both exact key agreement and the no-leak rejection controls. It prints `ATTACK kex-02-3 ... CONFIRMED`.

## kex-02-4: A copied certified public key enables an unknown-key-share

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified pMAKE-BW protocol, all three parameter sets, when certification permits duplicate public keys
Discovery: Trivial
Exploitation: One duplicate-key registration and one relayed honest session
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6J2L7XPCKMT7VFS4LRE7DSP3BMJRUFEV/)
Follow-up source: [AFS-KEX team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KWCCXWCNCLZBXRLN5GQJCMFUHCFSECXM/) and [further response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5LFINDPHMLECJ6YRWV7QCCMAV7J6JBFL/)

The protocol derives `K_SESSION = PRF(K_A,K_B)`. Neither party identity enters that KDF or a MAC. An attacker Eve registers a copy of Alice's public key under Eve's identity, relays an Alice–Bob exchange, and changes the cleartext `id_A` in round 3 to `id_E`. Alice accepts Bob, Bob's certification check accepts the same public key for Eve, and Bob accepts Eve; both honest parties derive the same key while disagreeing about its peer identity. The defect is specifically that the peer identity is not bound into the derived key.

The witness reproduces this unknown-key-share in 200 of 200 sessions at every parameter set using only public-key copying and message relay. The specification says authentication is obtained through public-key recovery and certification, but the formal Setup generates distinct honest public keys and excludes duplicate-key registration. Because the attack depends on a certification policy outside that model, it is a Medium identity-binding gap rather than a break inside the stated game.

### Follow-up Analysis

The team states that its certification model disallows duplicate public-key registration and that, in a deployment permitting it, identities should enter the key derivation. This agrees with the report's stated precondition and does not change the reproduced behavior under that precondition.

### Proposed fixes

The original post proposes including `id_A`, `id_B`, and a transcript hash in the session-key PRF. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kex-02 reproduce-protocol-findings
```

The pinned wrapper runs the copied-key relay at C128, C256, and C512 and requires equal keys together with different recorded peer identities. It prints `ATTACK kex-02-4 ... CONFIRMED`.

## kex-02-5: An unauthenticated responder observes decapsulation failures

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified pMAKE-BW protocol, all three parameter sets
Discovery: Trivial
Exploitation: Stable chosen-ciphertext reaction oracle; key recovery not demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/6J2L7XPCKMT7VFS4LRE7DSP3BMJRUFEV/)
Follow-up source: [AFS-KEX team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/KWCCXWCNCLZBXRLN5GQJCMFUHCFSECXM/) and [further response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/5LFINDPHMLECJ6YRWV7QCCMAV7J6JBFL/)

The KEM uses implicit rejection, and the initiator sends round 3 for both valid and invalid ciphertexts. An unauthenticated responder nevertheless knows the valid ciphertext's encapsulated key. It can decrypt the returned protected seed with the key derived for the valid path and check whether that seed reconstructs the initiator's certified public key. After a ciphertext modification triggers implicit rejection, this check fails, revealing the decapsulation-validity bit even though the message flow is unchanged.

At each parameter set, the validity check succeeded for 200 of 200 honest ciphertexts and failed for 200 of 200 deliberately modified ciphertexts. This confirms the observable reaction bit, not a recovery attack. The specification already argues that a fresh composite key permits at most one relevant failure observation per session. Aggregating useful conditions across independently refreshed composite keys has not been validated, and no natural-failure run or long-term-key recovery is claimed.

### Follow-up Analysis

The team emphasizes that the composite public key changes each session and argues that the resulting failure observations cannot be accumulated against one key. That is already the limitation stated here; no cross-session recovery is claimed.

### Reproducing

```sh
make -C kex-02 reproduce-protocol-findings
```

The pinned wrapper checks the honest and injected-failure seed-recovery controls at C128, C256, and C512. It prints `ATTACK kex-02-5 ... CONFIRMED`.
