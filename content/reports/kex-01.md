<!-- synchronized report: kex-01/report.md -->
Candidate: ADKEX (Authenticated Ding Key Exchange)
Family: Lattice (unilaterally authenticated KEM-based key exchange)
Archive: [ADKEX.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/ADKEX.zip) (SHA-256: `bbadecca0ce9d3f3131129b17c91e0ab89a81e077710e53f7a569a30475a23f2`)

## kex-01-1: The stated no-matching-session theorem is false for responder sessions

Severity: Medium
Status: Confirmed
Layer: Design
Affected: ADKEX security definition and Theorem 5.1
Discovery: Trivial
Exploitation: One ordinary adversarially initiated responder session
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-29
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AGQTR6256YQJPU76ZTC3RSLY44J7Y6T7/)

The specification defines a fresh session with no matching session and claims key indistinguishability for every such session (pages 31–32). The proof following Theorem 5.1 says that this case "can be proven similarly" to its matching-session wPFS case. This is false for the responder role. An active initiator claims an honest initiator's identity, satisfying the stated freshness condition, then chooses its ephemeral key and encapsulation, decapsulates the responder's reply, and knows the public transcript. It therefore computes the responder's real session key and distinguishes it from random with advantage `1/2` without a Reveal, StateReveal, or Corrupt query.

This does not attack an honestly matched exchange. It shows that the claimed no-matching-session case fails to account for the deliberately unauthenticated initiator: the theorem needs a role-scoped authentication goal rather than the stated all-session claim.

### Reproducing

Apply the experiment on physical PDF pages 31–32 to a completed responder session created by an active initiator. The session has no matching honest initiator session and remains fresh under the listed exclusions, while the initiator possesses all three inputs to the responder's KDF.

## kex-01-2: ADKEX-512 silently derives different keys in honest sessions

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted ADKEX-512 reference implementation
Discovery: Moderate
Exploitation: Honest-session correctness failure; no confidentiality or authentication attack demonstrated
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-29
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AGQTR6256YQJPU76ZTC3RSLY44J7Y6T7/)
Follow-up source: [DKEM/DKEX/ADKEX team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NRJXWUW3IRBVMQZEGW3DNPUVK6PW7YLG/)

ADKEX-512 inherits signed 16-bit arithmetic from its DKEM backend. Rare intermediate overflows make the two parties derive different shared secrets even though every API call reports success. A fresh deterministic run found the first mismatch at trial 148; a separate 3,000-session run found two mismatches. Identical controls over 3,000 ADKEX-128 and ADKEX-256 sessions found none.

This contradicts the specification's correctness condition, which requires matching honest sessions to output the same key except with negligible probability. It is Low because the demonstrated effect is a silent reliability failure, not key recovery or an authentication bypass.

### Follow-up Analysis

The team confirms 20 handshake failures in 20,000 ADKEX-512 reference sessions. Its instrumentation found that overflow and failure depend only on the public received ciphertext, not the long-term secret; the submitted AVX2 backend is unaffected, while NEON and Cortex-M4 share the defect.

### Proposed fixes

The team's [fix commit](https://github.com/dkemdkex/dkem-dkex/commit/8e3417a) proposes additional forward-NTT reductions in the scalar, NEON, and Cortex-M4 paths. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kex-01 reproduce-correctness
```

The witness uses the submitted API and prints `CONFIRMED kex-01-2` at the first honest ADKEX-512 mismatch.

## kex-01-3: Incoming message lengths are ignored before fixed-size reads

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted ADKEX-128, ADKEX-256, and ADKEX-512 reference implementations
Discovery: Trivial
Exploitation: Malformed-message out-of-bounds read and process termination; no disclosure demonstrated
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-29
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AGQTR6256YQJPU76ZTC3RSLY44J7Y6T7/)

`kex_generate_pass2_msg_b` discards `m1_len_bytes`, and `kex_derive_ss_a` discards `mb_len_bytes`, before parsing the supplied pointer as a complete fixed-size protocol message (`KEX_AlgorithmInstance.c:79–101` and `121–134`). A one-byte pass-1 allocation reaches a 32-byte read 767 bytes beyond that allocation at `dkecca.c:60`; AddressSanitizer traces it through `ADKEX_pass2_msg_b_derand` and the public pass-2 API.

Without a protected allocator boundary, adjacent heap bytes are consumed by encapsulation, transcript hashing, and key derivation while the API still returns success. The out-of-bounds `ct_S` is also passed to decapsulation at `adkex_derand.c:78`. The returned message contains a KEM ciphertext and derived transcript values rather than the adjacent bytes themselves, and no recovery channel has been demonstrated. The confirmed impact is therefore an attacker-triggered out-of-bounds read, with no demonstrated memory disclosure or control-flow impact, hence Low.

### Reproducing

```sh
make -C kex-01 reproduce-truncated
make -C kex-01 clean-reproducers
```

The first command builds the submitted ADKEX-128 source with AddressSanitizer, supplies a one-byte message with length one, checks for the heap-buffer-overflow trace, and prints `CONFIRMED kex-01-3`.
