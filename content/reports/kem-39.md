<!-- synchronized report: kem-39/report.md -->
Candidate: WeaverKEM
Family: Lattice (Module-LWR)
Archive: [Weaver.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Weaver.zip) (SHA-256: `9b0bad96e9bc836b0ff811492a70891066df5634ee47fda4d1518dccd4e09927`)

## kem-39-1: PRF substream reuse violates the IND-CPA proof's independence premise

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Non-trivial
Exploitation: Shared PRF substream and violated proof premise confirmed; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Weaver submitters' 2026-09-24 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TYYRYC5JRX3WVQTN3R66KOV2YWDA5EKP/)

The specification's encryption proof models randomized inverse-q lifting and the ephemeral secret `r` as independent PRF outputs obtained under distinct counters.

In the implementation, `polyvec_invq` receives its nonce by value and consumes counter 0 and later substreams internally. Its caller observes only one increment and begins sampling `r` at counter 1. The CBD input for `r[0]` is therefore a prefix of the same `PRF(seed1, 1)` stream already consumed by inverse-q lifting, with additional overlap depending on rejection and vector consumption.

The counter reuse is present in WeaverKEM-128, WeaverKEM-256, and WeaverKEM-512 and directly contradicts the independence premise used in Game 2 of the submitted proof. The correlation is confirmed, but it has not yet been converted into a concrete IND-CPA distinguisher or key-recovery algorithm. This is therefore a probable claim violation, not a claimed complete break.

The [submitters acknowledged the reference-code nonce propagation on 2026-09-24](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TYYRYC5JRX3WVQTN3R66KOV2YWDA5EKP/). This report concerns the archived submission.

### Proposed fixes

The [Weaver submitters' response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TYYRYC5JRX3WVQTN3R66KOV2YWDA5EKP/) proposes changing `polyvec_invq` to accept a `uint8_t *nonce`, so the caller observes the nonce advances performed inside the function. This section records the proposal without evaluating it.

### Reproducing

Fetch the official archive and compare `WeaverKEM-128/indcpa.c` lines 337–368
with `WeaverKEM-128/poly_invq.c` lines 88–103. `nonce++` passes zero by value
to `polyvec_invq`; that function consumes further nonces internally, while the
caller next uses one for `r`. The same data flow occurs in the 256 and 512
reference variants. This verifies the shared PRF substream, not a concrete
IND-CPA distinguisher.

```sh
IDS=kem-39 ./download.sh
./extract.sh kem-39
rg -n 'polyvec_invq|poly_getnoise_eta2|prf\(' kem-39/Implementations/Reference_Implementation/WeaverKEM-128/{indcpa,poly_invq}.c
```

## kem-39-2: WeaverKEM-256 omits its high-layer BCH decoder

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: WeaverKEM-256 reference and optimized implementations (Weaver-1024 in the specification)
Discovery: Trivial
Exploitation: Correctable high-layer errors change the decapsulated message; actual honest KEM failure rate unmeasured
Credit: Yijian Liu (with AI assistance)
Date: 2026-09-24
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DJRC6VQK5TYNKMAJBD2MIKUH7EAZ4VO6/)

Table 3's Weaver-1024 failure estimate (`2^-231.7` overall) assumes a high-layer BCH(255,223,4) decoder. The archived WeaverKEM-256 `poly_frommsg` encodes this redundancy, but the `WEAVER_MODE == 3` `poly_tomsg` branch in both submitted implementation families copies the hard-decision high bits into the message without calling the included `decode_bch_high_nibbles`. Other modes do call their high-layer decoder. Thus Table 3's correction-based bound does not describe the submitted implementations; no replacement failure probability or key-recovery attack is claimed.

### Follow-up Analysis

Zhenyu Xiong and Mingsheng Wang's [2026-09-30 Weaver analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/N4VESPWVOKXHJJABPIENYA2GYFGLBC7K/) models the submitted decoder rather than the specified BCH-correcting decoder. It estimates an honest-ciphertext DFR near `2^-47.5` under its exact-noise model, or about `2^-45.5` when initialized from the specification's per-bit rate, rather than the claimed `2^-231.7`. Its failure-boosting estimates are about `2^41` to `2^47` decapsulation queries. These figures are model extrapolations, not raw observations of such rare honest failures or a completed key recovery, so the finding remains Medium.

### Reproducing

```sh
D=kem-39/Implementations/Reference_Implementation/WeaverKEM-256
T=$(mktemp -d)
gcc -O2 -DWEAVER_MODE=3 -I"$D" kem-39/reproduce_high_bch_omission.c \
    "$D"/{msgenc,bch_high,bch_low,reduce}.c -o "$T/repro"
"$T/repro"
```

The witness starts with a correctly encoded zero message, injects one high-layer bit error, and obtains `0x80` from the submitted decoder; the included BCH decoder corrects the same bit to `0x00`. This demonstrates the omitted correction, not the frequency of naturally occurring ciphertext failures.

## kem-39-3: BCH decoders mis-correct some errors within their designed radius

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: WeaverKEM-256 and -512 reference and optimized implementations (Weaver-1024 and -2048 in the specification)
Discovery: Moderate
Exploitation: Occasional decoder failure at or below the advertised correction radius; no target-level DFR or key-recovery failure demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's Weaver analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/N4VESPWVOKXHJJABPIENYA2GYFGLBC7K/)

The Berlekamp–Massey discrepancy update in both the high- and low-layer BCH decoders sums locator coefficients only through iteration index `i+1`, rather than through the current locator-polynomial degree (`bch_high.c:209`, `bch_low.c:212`). When that degree grows faster than the iteration index, a required term is omitted and the decoder can mis-correct patterns whose weight is still within its advertised radius. The radius-two WeaverKEM-128 decoder is unaffected.

At exactly four errors, the archived WeaverKEM-256 high and low decoders recover 19,923/20,000 and 19,720/20,000 random trials. At exactly seven errors, WeaverKEM-512 recovers 19,832/20,000 and 19,398/20,000. A patched-loop control recovers 20,000/20,000 at every weight through the designed radius, while both versions fail at one error beyond it. This establishes a narrow robustness defect, but this report does not independently establish its contribution to the complete KEM's honest-failure rate.

### Proposed fixes

The [original post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/N4VESPWVOKXHJJABPIENYA2GYFGLBC7K/) proposes changing the discrepancy loop in both BCH decoders to `for (j = 1; j <= t && j <= 2*i+2; j++)` and adding unit tests at every error weight through `t`. This section records the proposal without evaluating it.

### Reproducing

The pinned public artifact builds isolated original and patched copies, runs direct and codec-level tests, checks a minimal failing message, and compares KAT hashes:

```sh
sh kem-39/reproduce_bch_decoder.sh
```

In the archived WeaverKEM-256 tree, the whole-codec original and patched controls both still fail because a separate omission of the high-layer decoder precedes this BCH-loop defect. The direct decoder tests isolate the discrepancy-loop defect described here.

## kem-39-4: Matrix and lifting samplers differ from the normative parsers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized implementations; lifting in all sets and matrix expansion in WeaverKEM-256/-512
Discovery: Trivial
Exploitation: Independent implementations following the PDF derive different polynomials; no cryptographic attack demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's Weaver analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/N4VESPWVOKXHJJABPIENYA2GYFGLBC7K/)

The specification's `ParseUniformq` consumes non-overlapping `ceil(log2 q)`-bit candidates. For `q=7681`, the WeaverKEM-256 and -512 implementations instead consume 16-bit words and apply Lemire's multiply-and-reject map. Both methods are uniform, but map the same XOF byte stream to different public matrices.

The randomized public-key lifting also differs in every set. Algorithm 3 derives each coefficient's bucket index from the separately domain-separated `SampleIndex(rho,i*n+j,|B|)`. The implementations instead draw a sequential PRF stream for each polynomial and continue it on rejection. This does not establish a bias, but it makes the normative construction and submitted KAT implementation non-interoperable and means the proof's specified random variables are not the ones instantiated by the source.

### Reproducing

```sh
python3 kem-39/reproduce_spec_mismatches.py
```

The certificate checks the PDF requirements and all six reference and optimized source trees.

## kem-39-5: Message encoding uses the wrong half-modulus

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All three reference and optimized implementations
Discovery: Trivial
Exploitation: Specification/code interoperability mismatch; no security consequence demonstrated
Credit: Zhenyu Xiong and Mingsheng Wang, with AI assistance
Date: 2026-09-30
Original source: [Xiong and Wang's Weaver analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/N4VESPWVOKXHJJABPIENYA2GYFGLBC7K/)

Weaver's message encoder specifies the high-layer representative `(q-1)/2`. The implementations define `WEAVER_HALFQ` as `(q+1)/2` and use it in both encoding and the lower-layer decision. Since all Weaver moduli are odd, these values differ by one: 1664 versus 1665 for `q=3329`, and 3840 versus 3841 for `q=7681`.

Encapsulator and decapsulator share the submitted convention, so self-generated tests remain consistent. An implementation following the normative algorithms, however, does not reproduce the submitted encoding and KAT behavior. No elevated DFR or confidentiality break is demonstrated.

### Reproducing

```sh
python3 kem-39/reproduce_spec_mismatches.py
```

## kem-39-6: The IND-CPA hybrid needs a public-key-dependent shift not covered by its assumption

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Weaver-640, -1024, and -2048 (submitted as WeaverKEM-128, -256, and -512); Theorem 4.5's Game 2 to Game 3 transition
Discovery: Moderate
Exploitation: The fixed-offset assumption does not directly justify the adaptive challenge-message hybrid; no IND-CPA distinguisher or key recovery demonstrated
Credit: Haotian (NGCC PKC Forum sender), with ChatGPT assistance
Date: 2026-10-21
Original source: [Haotian's PKC Forum comment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/VM2AQVK23DIQDOXRBZZTAMO6OD6BTL6K/) and [harness issue #34](https://github.com/ngcc-dev/ngcc-harness/issues/34)

Definition 4.2 (printed p. 27) defines Shifted-MLWR for a **fixed** public
offset `Δ`. In Theorem 4.5 (printed pp. 28–30), however, the IND-CPA
adversary sees `pk = (A, Compressq(T, d_t))` before choosing its two challenge
messages. The Game 2 to Game 3 transition then uses
`Δ_b = (0, MsgEncode(μ_b))ᵀ` for the chosen message. Thus `Δ_b` can depend on
the public key and hence on the challenge matrix assembled from `A` and `T`.
A reduction given a sample for a predetermined `Δ` cannot generally choose
the required `Δ_b` only after it receives the adversary's messages.

Corollary A.9 (printed pp. 54–55) explicitly covers each *fixed* message.
Its bound being uniform over fixed messages does not by itself exchange the
quantifiers to cover a message selected after seeing the public matrix. An
adaptive-offset reduction, or an additional joint-distribution argument,
could close this gap; none is supplied for this game transition in the frozen
specification. Appendix A.4's pre-rounding statistical-distance argument
appears compatible with an offset computed from the public matrix, but the
appendix also says its sufficient entropy conditions are not established for
the concrete sets. Thus the immediate gap is the fixed-offset formulation of
the heuristic assumption used in Theorem 4.5, not evidence that the
submitted ciphertexts are distinguishable or that Weaver's concrete
parameters miss their target. The stronger adaptive assumption remains to
be justified for those sets, which is why this stays Medium.

### Reproducing

```sh
python3 kem-39/reproduce_adaptive_offset_gap.py
```

The certificate checks the fixed-offset definition, the adaptive challenge
game and the fixed-message corollary in the frozen specification. Its small
quantifier example illustrates why a bound for every predetermined offset
does not alone imply the same bound for offsets chosen from the public matrix;
it is not a Weaver attack.

## kem-39-7: Decapsulation decodes and re-samples with secret-dependent branches and addresses

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: WeaverKEM-128, -256 and -512, reference and optimized implementations; the sampler loop affects -256 and -512 only
Discovery: Moderate
Exploitation: Local branch and address trace of decryption errors and of coin-derived values before the re-encryption check; no key recovery demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15
Three steps of decapsulation depend on secret values in their control flow or memory addresses.

- **BCH decoding.** `poly_tomsg` decodes the noisy message with `decode_bch_low` and `decode_bch_high` before the re-encryption check (`indcpa.c:419`, `msgenc.c:176–211`). The decoder indexes logarithm tables with syndrome values, branches on `if (tmp > elp->deg)` in the error-locator loop (`bch_low.c:191`), and writes each correction at the error position, `data[errloc[i]/8]` (`:320`). The trace shows whether and where a chosen ciphertext decrypted with errors.
- **Lifting.** The public-key lift accepts three-bit values under `t[j] < BUCKET_SZ[…]` (`poly_invq.c:76`). The values come from a PRF keyed by the encryption coins, which re-encryption derives from the decrypted message. The specification calls these inputs public (§4.3, p. 36); they are not.
- **Noise sampling.** `popcount_u32` loops `while (x)`, so its trip count is the bit length of each secret sampler input (`cbd.c:25–31`). WeaverKEM-256 and -512 use it for the secret, the encryption randomness and its re-derivation.

The specification acknowledges that the decoder relies on table lookups indexed by secret values and that a constant-time decapsulation would cost about 10% (p. 36). No oracle or recovery was built.

Constant-time fix (moderate): a constant-time BCH decoder with full table scans and masked correction, masked acceptance in the lift, and a fixed-length population count.

### Reproducing

```sh
d=kem-39/Implementations/Reference_Implementation/WeaverKEM-256
sed -n '188,193p' "$d/bch_low.c"; sed -n '316,320p' "$d/bch_low.c"
grep -n 'BUCKET_SZ\[r\[ctr\]\]' "$d/poly_invq.c"; sed -n '25,31p' "$d/cbd.c"
```

This is a source witness for the four sites.

## kem-39-8: A ciphertext with exactly t errors in a BCH codeword writes past the decoder's error-location array

Severity: High
Status: Confirmed
Layer: Implementation
Affected: WeaverKEM-128, -256 and -512 reference and optimized implementations (identical decoders by source; the witness runs the reference)
Discovery: Moderate
Exploitation: Unauthenticated stack write of 4 bytes from a crafted ciphertext; the value written is a fixed constant; a Clang `-O2` build of WeaverKEM-128 crashes, while GCC builds place a dead slot there
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-19

`chien_search` stores `roots[count] = n − i` on every step, before it knows whether the step found a root, into the caller's `unsigned int errloc[BCH_T]` (`bch_low.c:260`, `:388` in the nibble variant, `bch_high.c:257`). `count` reaches `t` when the codeword holds exactly `t` errors, and the store then writes `errloc[BCH_T]`, one element past the array. The last value written is the constant `ecc_bits`; the ciphertext decides only whether the write happens.

A ciphertext with `u = 0` and `v` chosen to put exactly `t` errors into one BCH codeword gave an AddressSanitizer stack-buffer-overflow WRITE of size 4 in the low-layer decoder at all three levels, and in the high-layer decoder at WeaverKEM-128 and -512 (WeaverKEM-256 has no high-layer decoder); `t − 1` errors gave none. Honest ciphertexts never reach it, but about one in three random WeaverKEM-128 ciphertexts do, in the high-layer decoder. With Clang 21 at `-O2` the slot past `errloc` in `decode_bch_high` holds the spilled `data` pointer, and WeaverKEM-128 decapsulation of such a ciphertext dies with SIGSEGV; with one error, or with `errloc[BCH_T + 1]`, it returns 0. GCC at `-O0` to `-O3`, including the submitted `-O3 -fomit-frame-pointer`, places dead storage there, and the decoded messages are unchanged.

The array needs `BCH_T + 1` entries, or the store must move inside the root test. An input-triggered stack write from an untrusted ciphertext, with a demonstrated crash, is High.

### Reproducing

```sh
sh kem-39/reproduce_bch_bounds.sh
```

The witness builds the three reference sets with AddressSanitizer and an observation hook, crafts the t-error ciphertexts, and runs the Clang `-O2` crash with the one-error and enlarged-array controls (that part is skipped without Clang).

## kem-39-9: Decapsulation reads past the error-locator array and past a short ciphertext

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: WeaverKEM-256 and -512 for the error-locator read; all three sets for the ciphertext length; reference and optimized implementations
Discovery: Trivial
Exploitation: Out-of-bounds stack reads on every honest WeaverKEM-256 and -512 decapsulation that write back unchanged values, and an out-of-bounds read of a caller-supplied short ciphertext; no disclosure or corruption shown
Credit: LK-PQC-Hunter (NGCC PKC Forum sender), using the LKQ PQC Hunter automated tool
Date: 2026-11-19
Original source: [LK-PQC-Hunter's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/SCHPYCDJBS43AXI326FCVKOXSY4TQDJE/)

`compute_error_locator_polynomial` updates `elp->c[j + k]` with indices up to `3t − 2` in a `2t + 1`-entry stack array (`bch_low.c:184`, `bch_high.c:181`). Under AddressSanitizer every honest WeaverKEM-256 and -512 decapsulation reports a stack-buffer-overflow READ there; WeaverKEM-128 is clean. The value XORed in is nonzero only for indices up to `2t − 1`, so the out-of-range bytes are rewritten unchanged: an instrumented copy saw no nonzero out-of-range XOR over honest, crafted and random ciphertexts and exhaustive or random sweeps of the decoder inputs, and a symbolic sweep of all discrepancy patterns gives the same bound.

All six `kem_dec` wrappers discard `ct_len_bytes`. An honest ciphertext in a heap buffer one byte short, declared at that length, is read past its end at all three levels; the full-length buffer is clean. Callers that pass complete ciphertexts are unaffected by this part.

### Reproducing

```sh
sh kem-39/reproduce_bch_bounds.sh
```
