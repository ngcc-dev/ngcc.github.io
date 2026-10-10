<!-- synchronized report: kex-03/report.md -->
Candidate: CreTAKE
Family: Lattice (composite AKE: KEM + signature)
Archive: [CreTAKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/CreTAKE.zip) (SHA-256: `0b356074741bc20fa82132719e1678e001083b9746f5c4c582425b727b511741`)

## kex-03-1: Bits-versus-bytes error reduces the ephemeral secret to 64 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, 23 source files including all six S2S instances
Discovery: Trivial
Exploitation: 2^64 offline
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [CreTAKE team's 2026-10-10 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/T624LE7EOQZEMDHF5TZI42TYSPMGW3YP/)

The responder requests 64 bytes (512 bits) of fresh randomness:

`get_random_number(&drng_algorithm, buf, SEED_BYTES * 8ULL)`

It then expands that value with:

`pseudoXOF((MSG_LEN_BYTES + SEED_BYTES) * 8, buf, SEED_BYTES, buf2)`

The third `pseudoXOF` argument is a bit count, but `SEED_BYTES` is 64. Only the first eight bytes of the 64-byte buffer are absorbed. The correct `SEED_BYTES * 8` form appears commented out immediately above related call sites. The erroneous pattern occurs in 23 reference source files and is preserved by every submitted test vector.

In the six S2S instances, this 64-bit value is the only secret input to the session-key computation. A passive eavesdropper enumerates the `2^64` possible inputs, regenerates the deterministic encryption coins and candidate plaintext, and matches the observed ciphertext. This recovers the session key offline at every claimed 128-, 256-, and 512-bit level.

### Reproducing

This is a source and key-space review; a `2^64` search is not run. Fetch the
official archive and inspect the responder call in, for example,
`CreTAKE128/CreTAKE-S2S-BiT128-eZEN128/KEX_AlgorithmInstance.c` line 156. The
second `pseudoXOF` length argument is 64 **bits**, not the intended 64 bytes.

```sh
IDS=kex-03 ./download.sh
./extract.sh kex-03
rg -n -F 'buf, SEED_BYTES, buf2' kex-03/Implementations/Reference_Implementation
```

The same defect reduces the claimed weak forward secrecy of K2S and S2K instances to `2^64` after compromise of the complementary long-term KEM key. This is an implementation error, not a cryptanalytic attack on the specified primitives.

### Proposed fixes

The [CreTAKE team's 2026-10-10 reply](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/T624LE7EOQZEMDHF5TZI42TYSPMGW3YP/) says it corrected the affected hash/XOF bit-length arguments in a revision to be released at the next permitted update. This is recorded without evaluating the revision.

## kex-03-2: Omitting signatures from the KDF breaks transcript matching

Severity: Critical
Status: Confirmed
Layer: Design
Affected: All 18 specified K2S, S2K, and S2S instances
Discovery: Trivial
Exploitation: One alternate valid signature and standard AKE reveal queries
Credit: ManojG
Date: 2026-09-30
Original source: [ManojG's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/E7ZJE4X2VS7GIUMYIAAJXKRNIUYPYUWG/)
Follow-up source: [CreTAKE team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SXWBPLGXZT2GP6LFHK24VX3Y53A76GTC/)

CreTAKE says its KDF binds the complete public transcript and claims IND-AA or IND-StAA security for the four frameworks (§4.1). However, Figures 1, 2, and 4 include signature bytes in the exchanged messages while their KDF inputs omit those signatures. The reference implementation does the same in every signature-bearing instance.

An adversary corrupts the signature-credential holder and replaces its valid signature with a distinct valid signature on the same authenticated string. It chooses that holder's session as the test session, without revealing its state; this is not excluded by the adopted [IND-(St)AA game](https://eprint.iacr.org/2018/928). The peer accepts, but the two sessions are non-matching because their complete wire transcripts differ. Their KDF inputs and session keys are nevertheless identical. Revealing the non-matching peer session therefore supplies the test session's real key and distinguishes it from random. This is a polynomial-time break of the claimed AKE security, hence Critical; it requires no signature forgery.

The submitted BiT signer is randomized. Two calls with the same key and message readily produce distinct signatures that both verify, so the condition needed by the attack holds in the concrete instances rather than only for a contrived EUF-CMA scheme.

### Proposed fixes

The CreTAKE authors' revised KDFs, as quoted in the original post, include the signature bytes in the transcript hash. This section records the proposal without evaluating it.

The later team response says its revised reductions carry the complete signed messages through the games and announces separate framework-and-role tags when credentials are shared. These proposals are recorded without evaluating them.

### Reproducing

```sh
make -C kex-03 lib/libCreTAKE-K2S-PLAC128-BiT128.so
python3 kex-03/reproduce_binding_attacks.py
```

The witness checks all 18 KDF implementations, generates two distinct valid BiT signatures on one string, and shows the resulting distinct transcripts retain the same KDF input and key.

## kex-03-3: The generic double-key KEM fails its claimed first-key CCA game

Severity: High
Status: Confirmed
Layer: Design
Affected: Figure 7 and the five generic PolarLAC/ZEN double-key KEM instances
Discovery: Trivial
Exploitation: Two allowed second-key leaks and one allowed decapsulation query
Credit: ManojG
Date: 2026-09-30
Original source: [ManojG's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/E7ZJE4X2VS7GIUMYIAAJXKRNIUYPYUWG/)
Follow-up source: [CreTAKE team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SXWBPLGXZT2GP6LFHK24VX3Y53A76GTC/)

Figure 7 derives the double-key KEM output as `h(pk1,K1,m')`, omitting the second public key and both ciphertext components. The five generic `twokem.c` implementations reproduce this construction. It is not `[IND-CCA,IND-CPA]` secure under Definition 8.

The first-key CCA game lets the adversary obtain two generated second-key pairs. For the challenge `(c1*,c2*)` under `pk2*`, it decrypts `c2*` with the leaked `sk2*`, re-encrypts the recovered `m'` under the other leaked `pk2'`, and asks the permitted CCA query `(pk2',(c1*,c2'))`. Decapsulation recovers the unchanged `K1` and `m'`, so it returns exactly the challenge key. The adversary distinguishes with overwhelming probability without learning the first secret key.

This breaks an explicitly claimed component property. The outer K2K framework hashes the complete AKE transcript, so the post does not establish a session-key attack on CreTAKE-K2K itself; the finding is therefore High rather than Critical.

### Proposed fixes

The original post proposes deriving the key from a domain-separation tag, both public keys, both ciphertexts, `K1`, and `m'`. It does not supply a proof. This section records the proposal without evaluating it.

The team separately proposes `K = h(pk', K1, m', c)` with the complete two-part ciphertext and says it will revise Figure 7 and the component proof. This proposal is recorded without evaluating it.

### Reproducing

```sh
python3 kex-03/reproduce_binding_attacks.py
```

The witness checks the five submitted generic implementations and executes the cross-key query algebra with a correctness-preserving PKE model. The attack depends only on PKE correctness and on the displayed KDF inputs.

## kex-03-4: Initiator length-unit error removes the NAXOS long-term-key binding

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All 12 S2K and S2S instances in the reference and optimized source trees
Discovery: Moderate
Exploitation: One permitted initiator StateReveal and public data recover the session key without search
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VFESLNXKIUQ44DF72VJJCBSVOHOEN6FO/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/996e9e01bb71210b4debd44e565f543833d0d135/cretake-naxos-binding)

The initiator hashes `r || sk_i` with a byte count passed to a bit-length API (for example reference `CreTAKE-S2S-BiT128-eZEN128/KEX_AlgorithmInstance.c:117,187` and `CreTAKE-S2K-BiT128-PLAC128/KEX_AlgorithmInstance.c:124,204`, against `auxfunc.c:460`; the other S2K and S2S instances make the same calls at nearby lines). It absorbs all 64 bytes of `r` but only 177, 464, or 1,072 bytes of the BiT secret key. Those bytes are exactly a public-key prefix. A permitted initiator StateReveal therefore supplies the only nonpublic input: the attacker regenerates the ephemeral wKEM key, decrypts the transcript, and derives the session key without search.

This contradicts the specification's state-reveal argument (physical pp. 19–20; Theorems 2 and 4 on physical pp. 23–26). All 12 reference instances recovered 20/20 keys. Changing the length to bits gave 0/20, while correcting only the responder's expansion length left recovery intact. Source inspection confirms the same call in all 12 optimized wrappers; four optimized ZEN runs hit an unrelated alignment crash on this host.

### Proposed fixes

The [CreTAKE team](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/T624LE7EOQZEMDHF5TZI42TYSPMGW3YP/) says it corrected the affected hash/XOF input lengths in a revision to be released at the next permitted update. This is recorded without evaluating the revision.

### Reproducing

```sh
./kex-03/reproduce_naxos_and_lengths.sh
```

## kex-03-5: Ignored KEX message lengths cause pre-authentication out-of-bounds reads

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All 25 CreTAKE instances in the reference and optimized source trees
Discovery: Trivial
Exploitation: Out-of-bounds reads on truncated unauthenticated messages; no disclosure, write, or control-flow effect demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with GLM-5.3 assistance
Date: 2026-10-05
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VFESLNXKIUQ44DF72VJJCBSVOHOEN6FO/) and [pinned verification package](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/996e9e01bb71210b4debd44e565f543833d0d135/cretake-naxos-binding)

The KEX wrappers parse fixed-size fields while discarding the caller's `m1_len_bytes` or `m2_len_bytes`. In K2S, for example, a buffer allocated to the attacker-supplied length is passed to PKE code that reads the fixed `TPK_LEN`; K2S and K2K reach these paths before authentication.

With buffers sized to the bytes received, AddressSanitizer reported invalid reads for all 150 tested truncations across the 25 reference instances. No out-of-bounds write, memory disclosure, or control-flow consequence was demonstrated, so this is Low.

### Proposed fixes

The [CreTAKE team](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/T624LE7EOQZEMDHF5TZI42TYSPMGW3YP/) says it will check expected message lengths before parsing or invoking the underlying primitives. This proposal is recorded without evaluation.

### Reproducing

```sh
./kex-03/reproduce_naxos_and_lengths.sh
```

## kex-03-6: POLARLAC reference and optimized vectors derive different shared secrets

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All 13 POLARLAC-based CreTAKE reference/optimized instance pairs
Discovery: Moderate
Exploitation: Cross-implementation key agreement can fail; no confidentiality attack is demonstrated
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NPW7UHH4G3Y5MTSWGK7H6KHPKFFCUIMD/)

In the frozen official archive, each of the 13 POLARLAC-based reference and optimized KAT pairs starts with the same 64-byte seed but records a different shared secret. All 12 ZEN-based pairs agree under the same check. For example, K2K-PLAC128's first reference and optimized `SS` fields begin `8DA4C53F` and `35C82311`. We independently checked the archive's published SHA-256 and these vector fields. The forum additionally reports that mixed reference/optimized parties complete `derive` but obtain different keys on 4/4 seeds. That protocol experiment was not rerun here; the archived vectors alone establish inconsistent submitted implementations, not which one is correct. This is a Low interoperability defect.

### Proposed fixes

The [CreTAKE team](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/T624LE7EOQZEMDHF5TZI42TYSPMGW3YP/) says the PolarLAC team will correct the underlying reference/optimized incompatibility. This proposal is recorded without evaluation.

### Reproducing

```sh
python3 kex-03/reproduce_kat_interop.py
```

The script downloads the pinned official archive, verifies its SHA-256, and checks first-record seeds and shared secrets for all 25 instance pairs. It exits with SKIP status 77 if the archive is unavailable; `--archive /path/to/CreTAKE.zip` permits offline replay.

## kex-03-7: K2K-PLAC512 encryption coins depend on only 128 message bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: CreTAKE-K2K-PLAC512 and -PLAC512Star, reference and optimized implementations
Discovery: Moderate
Exploitation: About 2^128 offline candidate encryptions, given the initiator StateReveal allowed for an honestly matched session
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool; session-key-recovery extension by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-06
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NPW7UHH4G3Y5MTSWGK7H6KHPKFFCUIMD/)

In the reference trees for `CreTAKE-K2K-PLAC512` (`twokem.c:107,155`) and `CreTAKE-K2K-PLAC512Star` (`twokem.c:108,156`), `sizeof(buf3) = 128` is passed to `pseudoXOF` as a *bit* length. The XOF copies only 16 bytes (`auxfunc.c:482–507`), all from the 64-byte random message `m`; the remaining message bytes and public-key digest do not affect its output. Thus the two encryption seeds and double-key KEM secret have at most 128 bits of input entropy. The 128/256-bit and ZEN512 K2K variants use the correct `* 8` length. The certificate below inspects and executes only the reference tree; the optimized call sites are source-inspected.

The first POLARLAC ciphertext component is generated from an encryption seed and public key, independently of `m` (`POLARLAC-512/pke.c:144–190`). An attacker can enumerate the 2^128 message prefixes, derive candidate seeds, and check that component against the observed ciphertext. This recovers the K2K secret `k_i`; the search is a concrete bound, not a run we performed. The full ciphertext is still compared on decapsulation—this is not a truncated re-encryption check.

CreTAKE claims IND-StAA for K2K (§4.2.2 and Theorem 3). In the [adopted model](https://iacr.org/archive/pkc2020/12110176/12110176.pdf), an initiator StateReveal of an honestly matched test session is permitted without corrupting that party's long-term key (Figure 14, physical pp. 23–24). The revealed initiator state contains the independent `k_j` (`KEX_AlgorithmInstance.c:131–145`). Alternatively, corruption of the responder's static KEM key permits decapsulation of the public `ct_j` to obtain `k_j`. With both `k_i` and `k_j`, the attacker computes the transcript-bound session key. This below-target attack is conditional on one of those preconditions; a passive attack on every session is not claimed.

### Proposed fixes

The [CreTAKE team](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/T624LE7EOQZEMDHF5TZI42TYSPMGW3YP/) says it corrected the affected XOF length argument in a revision to be released at the next permitted update. This is recorded without evaluating the revision.

### Reproducing

```sh
python3 kex-03/reproduce_k2k_prefix.py
```

The certificate checks both 512-bit PLAC source variants, the bit-length conversion, and the session-state layout. It also tests that changing bytes after the first 16 does not alter the submitted XOF's effective input. It does not perform the 2^128 search.
