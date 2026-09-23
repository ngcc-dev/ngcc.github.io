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

The specification defines Mito-E by distance-informed errors-and-erasures decoding. The modified inner Reed–Muller decoder returns an erasure count `t` and erasure positions `pos`; the outer Reed–Solomon decoder is then supposed to use them, with correctness condition `2ν+t ≤ N−K`. The E-variant DFR calculation relies on this extra decoding capacity.

All twelve submitted Mito-E source trees (six parameter variants, each in reference and optimized form) compute `t` and `pos` but immediately discard both. They call the same two-argument, errors-only `reed_solomon_decode(m,tmp)` used by the baseline scheme. Thus the shipped E variants do not implement the algorithm whose DFR is claimed in the PDF. Some submitted trees also hard-code `PARAM_ALPHA=7` where the specification's E-variant DFR tables use 9 or 11. Without a fresh analysis of the shipped decoder and constants, this is not yet a quantified key-recovery attack.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id kem-23-1
```

The `kem-23-1` check verifies this data-flow defect in the six reference
E-variant source trees retained in the public harness and the corresponding
errors-and-erasures requirement in the PDF. The command does not inspect the
optimized trees.

To check the six optimized counterparts mentioned above, download the
SHA-256-identified official archive and inspect each optimized E-variant's
`code.c` and `reed_solomon.h` for the same discarded `t`/`pos` values and
two-argument `reed_solomon_decode(m, tmp)` call:

```sh
IDS=kem-23 ./download.sh
./extract.sh kem-23
rg -n 'reed_muller_decode\(tmp, pos, em\)|reed_solomon_decode\(m, tmp\)' kem-23/Implementations --glob code.c
```
