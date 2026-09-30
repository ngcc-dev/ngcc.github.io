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

A related initiator-side call passes `SEED_BYTES * 8` as the requested output length but only `SEED_BYTES + SKI_LEN` as the `pseudohash` input bit count. In those instances `SKI_LEN/8 > 56`, so all 64 random bytes are still absorbed and this second units error does not reduce entropy further. It confirms that the bits-versus-bytes confusion is systematic.

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

CreTAKE says its KDF binds the complete public transcript and claims IND-AA or IND-StAA security for the four frameworks (§4.1). However, Figures 1, 2, and 4 include signature bytes in the exchanged messages while their KDF inputs omit those signatures. The reference implementation does the same in every signature-bearing instance.

An adversary corrupts the signature-credential holder and replaces its valid signature with a distinct valid signature on the same authenticated string. It chooses that holder's session as the test session, without revealing its state; this is not excluded by the adopted [IND-(St)AA game](https://eprint.iacr.org/2018/928). The peer accepts, but the two sessions are non-matching because their complete wire transcripts differ. Their KDF inputs and session keys are nevertheless identical. Revealing the non-matching peer session therefore supplies the test session's real key and distinguishes it from random. This is a polynomial-time break of the claimed AKE security, hence Critical; it requires no signature forgery.

The submitted BiT signer is randomized. Two calls with the same key and message readily produce distinct signatures that both verify, so the condition needed by the attack holds in the concrete instances rather than only for a contrived EUF-CMA scheme.

### Proposed fixes

The CreTAKE authors' revised KDFs, as quoted in the original post, include the signature bytes in the transcript hash. This section records the proposal without evaluating it.

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

Figure 7 derives the double-key KEM output as `h(pk1,K1,m')`, omitting the second public key and both ciphertext components. The five generic `twokem.c` implementations reproduce this construction. It is not `[IND-CCA,IND-CPA]` secure under Definition 8.

The first-key CCA game lets the adversary obtain two generated second-key pairs. For the challenge `(c1*,c2*)` under `pk2*`, it decrypts `c2*` with the leaked `sk2*`, re-encrypts the recovered `m'` under the other leaked `pk2'`, and asks the permitted CCA query `(pk2',(c1*,c2'))`. Decapsulation recovers the unchanged `K1` and `m'`, so it returns exactly the challenge key. The adversary distinguishes with overwhelming probability without learning the first secret key.

This breaks an explicitly claimed component property. The outer K2K framework hashes the complete AKE transcript, so the post does not establish a session-key attack on CreTAKE-K2K itself; the finding is therefore High rather than Critical.

### Proposed fixes

The original post proposes deriving the key from a domain-separation tag, both public keys, both ciphertexts, `K1`, and `m'`. It does not supply a proof. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kex-03/reproduce_binding_attacks.py
```

The witness checks the five submitted generic implementations and executes the cross-key query algebra with a correctness-preserving PKE model. The attack depends only on PKE correctness and on the displayed KDF inputs.
