<!-- synchronized report: kem-39/report.md -->
Candidate: WeaverKEM
Family: Lattice (Module-LWR)
Archive: [Weaver.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Weaver.zip) (SHA-256: `9b0bad96e9bc836b0ff811492a70891066df5634ee47fda4d1518dccd4e09927`)

## kem-39-1: PRF substream reuse violates the IND-CPA proof's independence premise

Severity: Medium
Status: Probable
Layer: Implementation
Affected: Reference implementation, all three parameter sets
Discovery: Non-trivial
Exploitation: Not yet demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Weaver submitters' 2026-09-24 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TYYRYC5JRX3WVQTN3R66KOV2YWDA5EKP/)

The specification's encryption proof models randomized inverse-q lifting and the ephemeral secret `r` as independent PRF outputs obtained under distinct counters.

In the implementation, `polyvec_invq` receives its nonce by value and consumes counter 0 and later substreams internally. Its caller observes only one increment and begins sampling `r` at counter 1. The CBD input for `r[0]` is therefore a prefix of the same `PRF(seed1, 1)` stream already consumed by inverse-q lifting, with additional overlap depending on rejection and vector consumption.

The counter reuse is present in WeaverKEM-128, WeaverKEM-256, and WeaverKEM-512 and directly contradicts the independence premise used in Game 2 of the submitted proof. The correlation is confirmed, but it has not yet been converted into a concrete IND-CPA distinguisher or key-recovery algorithm. This is therefore a probable claim violation, not a claimed complete break.

The [submitters acknowledged and fixed the reference-code nonce propagation on 2026-09-24](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TYYRYC5JRX3WVQTN3R66KOV2YWDA5EKP/). This report concerns the archived submission.

Each logical sampler must receive a disjoint domain or counter range, and the nonce consumed inside `polyvec_invq` must be returned to or advanced by its caller.

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
Affected: WeaverKEM-256 reference implementation (Weaver-1024 in the specification); optimized implementation reported but not independently checked
Discovery: Trivial
Exploitation: Correctable high-layer errors change the decapsulated message; actual honest KEM failure rate unmeasured
Credit: Yijian Liu (with AI assistance)
Date: 2026-09-24
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/DJRC6VQK5TYNKMAJBD2MIKUH7EAZ4VO6/)

Table 3's Weaver-1024 failure estimate (`2^-231.7` overall) assumes a high-layer BCH(255,223,4) decoder. The archived WeaverKEM-256 reference `poly_frommsg` encodes this redundancy, but its `WEAVER_MODE == 3` `poly_tomsg` branch copies the hard-decision high bits into the message without calling the included `decode_bch_high_nibbles`. Other modes do call their high-layer decoder. The forum post says the optimized implementation has the same omission; that source was not included in the available archive and is not independently verified here. Thus Table 3's correction-based bound does not describe the checked implementation; no replacement failure probability or key-recovery attack is claimed.

### Reproducing

```sh
D=kem-39/Implementations/Reference_Implementation/WeaverKEM-256
T=$(mktemp -d)
gcc -O2 -DWEAVER_MODE=3 -I"$D" kem-39/reproduce_high_bch_omission.c \
    "$D"/{msgenc,bch_high,bch_low,reduce}.c -o "$T/repro"
"$T/repro"
```

The witness starts with a correctly encoded zero message, injects one high-layer bit error, and obtains `0x80` from the submitted decoder; the included BCH decoder corrects the same bit to `0x00`. This demonstrates the omitted correction, not the frequency of naturally occurring ciphertext failures.
