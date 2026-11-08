<!-- synchronized report: kem-23/report.md -->
Candidate: Mito
Family: Code-based
Archive: [Mito.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Mito.zip) (SHA-256: `ee11788a3e8bf8653d18ade6580c47a331b91e7eac3e31a5a6750a4b4cfb827b`)

## kem-23-1: Mito-E discards every erasure before Reed–Solomon decoding

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Mito-1-E and Mito-2-E, all three parameter sets
Discovery: Trivial
Exploitation: DFR/conformance failure; concrete decapsulation failure rate not measured
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Yan, Cao, Tong and Zhang's independent analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/767XHHZ62MOHOCT2V6HBJT43R6FTXOZV/)

The specification defines Mito-E by distance-informed errors-and-erasures decoding. The modified inner Reed–Muller decoder returns an erasure count `t` and erasure positions `pos`; the outer Reed–Solomon decoder is then supposed to use them, with correctness condition `2ν+t ≤ N−K`. The E-variant DFR calculation relies on this extra decoding capacity.

All twelve submitted Mito-E source trees (six parameter variants, each in reference and optimized form) compute `t` and `pos` but immediately discard both. They call the same two-argument, errors-only `reed_solomon_decode(m,tmp)` used by the baseline scheme. Thus the shipped E variants do not implement the algorithm whose DFR is claimed in the PDF. All twelve set `PARAM_ALPHA=7`; the specification gives 9 for Mito-1-E-128 and 11 for Mito-1-E-512. Without a fresh analysis of the shipped decoder and constants, this is not yet a quantified key-recovery attack.

### Reproducing

```sh
IDS=kem-23 ./download.sh             # if orig/kem-23/orig.zip is absent
unzip -qo orig/kem-23/orig.zip -d kem-23  # if optimized sources are absent
python3 security/design_parameter_audit.py --report-id kem-23-1
```

The `kem-23-1` check verifies this data-flow defect in all twelve E-variant
source trees retained in the public harness—six reference and six optimized
trees—and checks the corresponding errors-and-erasures requirement in the
PDF.

[Yan, Cao, Tong and Zhang's 2026-11-08 analysis](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/767XHHZ62MOHOCT2V6HBJT43R6FTXOZV/) independently confirms the mismatch and computes conditional errors-only decoder bounds. Four of its six upper bounds (the 256- and 512-bit E sets) are weaker than their respective targets; both 128-bit sets meet their targets under those bounds. An upper bound above a target does not establish that the actual failure rate exceeds it. Their controlled correction-boundary tests report 0/96 successes for the submitted decoder and 96/96 for a corrected decoder, with neither path failing in 1,024 structured-noise frames per set. They also report that the RM decoder returns duplicate candidates for noiseless `0x00` and `0x80`, creating a zero confidence gap and false erasure marks: simply forwarding those marks fails all 96 noiseless zero-message tests. A repair therefore needs to address the duplicate-candidate behavior as well as the discarded erasure information. These controlled tests do not measure the submitted decoder's operational DFR.

```sh
rg -n 'reed_muller_decode\(tmp, pos, em\)|reed_solomon_decode\(m, tmp\)' kem-23/Implementations --glob code.c
```

## kem-23-2: Mito uses the external DRBG as an XOF

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All nine Mito reference implementations
Discovery: Trivial
Exploitation: Replacing the external RBG changes deterministic key, ciphertext and parsing expansions; the frozen submitted build is internally consistent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-03

Mito's function named `xof_init` is exactly `init_random_number(xof_ctx, seed, seed_size)`, and `xof_get_bytes` reads the external DRBG stream (`symmetric.c:50–67`). Key generation, parsing and encryption seed this wrapper from protocol values (`mito_pke.c:39–45,87`; `parsing.c:17–33`). Correct operation therefore depends on one particular RBG's deterministic stream.

The archive is self-consistent and no confidentiality break is asserted. The Low defect is using an external RBG contract where the scheme requires a specified XOF.

### Reproducing

```sh
python3 security/rbg_protocol_dependency.py --report-id kem-23-2
```

## kem-23-3: Short ciphertexts reach Mito's fixed-offset parser

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: All nine Mito parameter sets, reference and optimized decapsulation
Discovery: Trivial
Exploitation: A caller-supplied short ciphertext buffer causes an out-of-bounds read; no disclosure or key recovery is demonstrated
Credit: Hao Yan, Yuhang Cao, Yao Tong and Qiaosheng Zhang (Shanghai AI Lab; AI-assisted discovery, human verified)
Date: 2026-11-08
Original source: [Yan, Cao, Tong and Zhang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/767XHHZ62MOHOCT2V6HBJT43R6FTXOZV/)

All 18 `kem_dec` wrappers discard `ct_len_bytes` and pass only `ct` to `crypto_kem_dec` (`KEM_AlgorithmInstance.c:60–66`). Its parser copies the vectors and the 32-byte salt at fixed offsets (`parsing.c:63–69`), so a genuinely short buffer is read beyond its end before any check. With a heap copy one byte shorter than the ciphertext, passed with its true length, AddressSanitizer reports a heap-buffer-overflow read in the salt copy in all nine sets of both implementation families. Honest round trips through exact-size buffers raise no report.

The authors' analysis (§4.1.4) also describes recovering the adjacent byte with up to 256 decapsulation queries when that byte is stable and key equality is observable. That extension is not reproduced here, so no memory disclosure is claimed. Extended buffers are ignored past the fixed length; that alias alone is not a finding for a fixed-size ciphertext domain.

The wrapper should reject any `ct_len_bytes` other than `CIPHERTEXT_BYTES` before reading the ciphertext.

### Reproducing

```sh
python3 kem-23/reproduce_short_ciphertext.py
```

The script checks the original archive against the SHA-256 above, fetching it if absent, and compiles each reference and optimized tree with AddressSanitizer, this repository's unmodified API shim and a small driver in a temporary directory. For each build it requires a clean honest round trip and a heap-buffer-overflow read in `mito_c_kem_from_string` for the one-byte-short buffer. It takes about 40 seconds and exits 77 if the compiler cannot build with AddressSanitizer.
