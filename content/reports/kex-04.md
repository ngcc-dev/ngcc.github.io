<!-- synchronized report: kex-04/report.md -->
Candidate: DKEX (Ding Key Exchange)
Family: Lattice (mutually authenticated key exchange)
Archive: [DKEX.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DKEX.zip) (SHA-256: `979c22239b4a2fb6732e68029c06659f8a7b582c00ca163e1ec72874b227e117`)

## kex-04-1: DKEX-512 silently derives different keys in honest sessions

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted DKEX-512 scalar reference implementation
Discovery: Moderate
Exploitation: Honest-session correctness failure; no confidentiality or authentication attack demonstrated
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [DKEM/DKEX/ADKEX team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NRJXWUW3IRBVMQZEGW3DNPUVK6PW7YLG/)

DKEX-512 shares the 16-bit scalar NTT arithmetic used by DKEM-512 and ADKEX-512. Legitimate lazy butterfly intermediates at `q=7681` can exceed the signed 16-bit range, corrupting the reconciliation value. The specification nevertheless claims a failure probability of about `2^-167` (Table 2 and §3.3).

The team reports 9 mismatches in 20,000 complete DKEX-512 reference sessions. An independent fixed-seed run found an honest three-pass session mismatch at trial 1379 even though every API call reported success. This is a protocol reliability failure, not a demonstrated key-recovery or authentication attack, hence Low.

### Proposed fixes

The team's [fix commit](https://github.com/dkemdkex/dkem-dkex/commit/8e3417a) proposes additional forward-NTT reductions in the scalar, NEON, and Cortex-M4 paths. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kex-04/reproduce_correctness.py
```

The witness initializes honest long-term keys, runs complete authenticated three-pass sessions through the submitted API, and compares both derived keys.

## kex-04-2: DKEX ignores input lengths before fixed-size reads

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: DKEX-128, -256, and -512 x86 and AArch64 KEX APIs, plus the Cortex-M4 KEM wrappers; runtime witness on reference DKEX-128
Discovery: Trivial
Exploitation: Malformed-message out-of-bounds read and process termination; no disclosure demonstrated
Credit: DKEM / DKEX / ADKEX team
Date: 2026-10-01
Original source: [Team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/USUZ2CPOFPWB3JST6BFM4XLGDHGY7URA/)

The DKEX KEX wrappers discard the declared key, state, and message lengths before parsing fixed-size protocol objects (`KEX_AlgorithmInstance.c:71–171`). A truncated pass-1 message can therefore be read beyond its allocation while producing pass 2. The team confirms that the pattern affected the submitted DKEX KEX APIs. The Cortex-M4 package has no KEX API, but its `KEM_AlgorithmInstance.c` wrappers contain the same missing checks and were included in the team's repair.

The local DKEX-128 witness gives pass 2 a one-byte allocation and a declared length of one. AddressSanitizer catches the resulting fixed-size read. No returned disclosure, write, or control-flow effect is demonstrated, so the finding is Low.

### Proposed fixes

The team's [fix commit](https://github.com/dkemdkex/dkem-dkex/commit/c6c2faa) proposes exact checks for every fixed-size input and minimum checks for state buffers before any read or randomness draw. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kex-04 reproduce-truncated
```

## kex-04-3: DKEX-512 authentication has only a 256-bit key-generation space

Severity: Critical
Status: Confirmed
Layer: Design
Affected: DKEX-512 authenticated key exchange, reference and optimized ML-DSA-87 instantiations
Discovery: Moderate
Exploitation: At most 2^256 signing-seed trials and polynomial work per trial permit responder impersonation; the full search was not run
Credit: 923930258@qq.com (NGCC PKC Forum sender), with Xuanzhi Cryptography Large Model assistance; seed-space witness by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-13
Original source: [PKC Forum evaluation attachment, PROOF-004](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/7GVGL2Z2NBJHFZNFP6MNHFWC35GPHMOP/attachment/12/DKEX-Security-Evaluation-Report.md)

DKEX-512 claims a 512-bit classical level, but uses ML-DSA-87 for both parties' authentication (specification §2.1.3, physical p. 10; Table 1, p. 21). The submission itself says that this signature gives about 256 classical bits and that DKEX-512's authentication does not reach 512 bits (§3.2, p. 22; §6, p. 37). The submitted adapter takes exactly 32 bytes of signing-key-generation coins (`adkex_sig.h:53`, `adkex_sig_mldsa.c:58–65`); the vendored ML-DSA keygen reads precisely that seed and deterministically expands it (`dilithium/params.h:6`, `dilithium/sign.c:23–35`). Thus an attacker can enumerate at most `2^256` seeds, regenerate public keys until one equals the victim's, and sign a new transcript as that party. This is a concrete upper bound below the required 512-bit authenticated-KEX level, not an executed exhaustive search. It does not challenge the independent confidentiality of DKE-512.

The local witness regenerates the same public key from the same 32-byte seed, obtains a different key from a changed-seed control, and signs a fresh transcript accepted by the unmodified verifier but rejected after a transcript change. The protocol verifies the responder signature before deriving the initiator's secret (`adkex_derand.c:108`); a forged responder signature lets an attacker choose the response and complete an impersonated exchange.

### Reproducing

```sh
python3 kex-04/reproduce_signature_seed_cap.py
```

The script builds the submitted ML-DSA-87 implementation into a temporary directory and checks the seed-space and signature controls. It does not execute `2^256` trials.

## kex-04-4: A reflected responder signature completes a self-session

Severity: High
Status: Confirmed
Layer: Design
Affected: DKEX-128, DKEX-256 and DKEX-512, all submitted trees (byte-identical `adkex_derand.c`), when a party responds to a session whose claimed initiator key is its own
Discovery: Moderate
Exploitation: One reflected message against the unmodified libraries gives a responder session with no matching initiator session whose key the attacker computes; no break is claimed for a model that excludes same-key self-sessions
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

Both DKEX roles sign the same digest. Algorithm 16 (physical p. 18) has the responder compute `T ← H(LABEL_A, LABEL_B, pk_A, pk_B, M1, M2)` and send `σ_B ← Sign(sk_B, T)`. Algorithm 17 (p. 19) has the initiator sign that identical `T` as `m3 = σ_A`, and Algorithm 19 (p. 19) has the responder accept when `Verify(pk_A, T, σ_A)` succeeds. The code does the same: `adkex_derand.c:88` signs `T` for `σ_B`, `:117` signs the same `T` for `m3`, and `:146` verifies `m3` on that `T`. The labels are fixed constants concatenated in the same order in both roles (`adkex_derand.c:22–23`), so they do not separate the two roles' signed messages.

When `pk_A = pk_B = pk_P`, the attacker generates its own DKE ephemeral `(M1, sk_e)`, sends `M1` to party P's responder with claimed peer P, receives `m2 = (M2, σ_B)`, and returns `σ_B` unchanged as `m3`. P verifies its own signature under `pk_P` against the same `T` and accepts. P never ran an initiator session, so the session has no matching session. P is uncorrupted, so the session is fresh under Definition 5.1 (p. 26). The attacker knows `sk_e` and `T`, so it computes `ss = DKE.DeriveSecret(M2, sk_e)` and the session key `KDF(ss‖T)`. The attacker uses no signing key of P.

This contradicts §5.3 (p. 36), which states that the labels "ensure that the transcripts associated with the initiator and responder are distinct, even in the case pk_A = pk_B. As a result, the protocol remains resistant to self-reflection attacks." The no-matching argument on p. 29 (case 3) assumes that an honest signature on the same raw input implies a matching session of the opposite role; here the signature was made by the responder role of the session under test. Definition 5.1 does not say whether the owner and peer may coincide. That is why the rating is High rather than Critical. The precondition is a party that accepts a session whose claimed peer is itself, or two identities that share one signing key.

### Reproducing

```sh
make -C kex-04
python3 kex-04/reproduce_reflection_and_alias.py
```

The script runs the reflection against all three prebuilt DKEX libraries and requires the attacker's key to equal the responder's accepted key. Its controls require a bit-flipped reflected signature to be rejected, a reflection with `pk_A ≠ pk_B` to be rejected, and an honest exchange to agree; it also checks `adkex_derand.c:88` and `:117` when the sources are present. It runs in under a second and also prints the separate copied-key verdict for kex-04-5.

## kex-04-5: Copied certified keys enable identity misbinding

Severity: Medium
Status: Confirmed
Layer: Design
Affected: DKEX-128, DKEX-256 and DKEX-512 when certification permits duplicate public keys
Discovery: Trivial
Exploitation: One duplicate-key registration and one relayed honest exchange against the unmodified libraries; no break of the distinct-key formal model
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-17

DKEX binds the certified signing-key bytes, not the parties' identities. The transcript is `T = H(LABEL_A, LABEL_B, pk_A, pk_B, M1, M2)` (Algorithms 16 and 17, physical pp. 18–19; `adkex_derand.c:12–32`), both signatures are on `T`, and the key is `KDF(ss‖T)`. The specification says this transcript binding prevents unknown-key-share (p. 4) and that the key is "bound to both identities" (p. 22). However, `LABEL_A` and `LABEL_B` are fixed per-level constants (`ADKEX_parameters.h:27–42`), and no party name enters `T`.

If Eve obtains a certificate for Bob's public key under her own name, Alice can initiate to "Eve" using that certificate. Eve relays `m1`, `m2` and `m3` unchanged between Alice and Bob, and Bob runs the responder with Alice as his peer. `σ_B` verifies under the copied key, `σ_A` verifies under Alice's key, and both parties derive the same key: Alice records the peer as Eve and Bob records the peer as Alice. Revealing Alice's key then gives Bob's key, even though the two sessions do not match.

The formal setup states that each verification key "is certified and uniquely bound to identity P" (p. 28), which excludes this registration. The defect is therefore an identity-binding gap under a certification policy that admits duplicate keys, not a break inside the stated game.

### Reproducing

```sh
make -C kex-04
python3 kex-04/reproduce_reflection_and_alias.py
```

On all three prebuilt DKEX libraries, the script requires the relayed exchange to complete with equal keys while the two parties name different peers. As a control, it requires pass 3 to reject when Eve's certificate carries her own independently generated key. It runs in under a second and also prints the separate reflection verdict for kex-04-4.
