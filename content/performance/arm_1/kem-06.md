<!-- synchronized from harness: kem-06/perf_arm_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">arm_1</a> › <code>kem-06</code> · system: <a href="../x86_1/kem-06.md">x86_1</a> · <strong>arm_1</strong></p>

# kem-06 BRA — performance on AArch64 (system arm_1)

Independent measurement following the structure of the NICCS ARM self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: public-key algorithm; function: key encapsulation
- Algorithm: BRA
- Implementation versions measured: reference
- Parameter sets: `BRA-128`, `BRA-256`, `BRA-512`
- Security evaluation: [kem-06 report](../../reports/kem-06.md)
- Measurement method: [arm_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Additional/pc/content/content_2101560843625385984.html)

## 2. Assessment environment

| item | value |
|---|---|
| processor | Qualcomm Oryon (CPU 2, one core) |
| machine | ASUS Vivobook S 15 |
| clock | fixed 2.71 GHz (governor performance, minimum = maximum), boost off, SMT none |
| memory | 30562 MiB |
| OS / kernel | Ubuntu 26.04.1 LTS / 7.0.0-34-generic |
| compiler / build tool | gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0 / cmake version 4.2.3 |
| campaign start / end (UTC) | 2026-09-28T15:05:46 / 2026-09-29T08:43:52 |

## 3. Functional testing (KAT)

Each library was checked against the submitted KAT vectors (SHA-256 manifest `kem-06/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `BRA-128` | harness-default | BUILDFAIL |
| `BRA-256` | harness-default | BUILDFAIL |
| `BRA-512` | harness-default | BUILDFAIL |

## 4. Performance

| instance | operation | mean cycles | mean time | ops/s | median trial | n (trials × iters) |
|---|---|---|---|---|---|---|

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|

## 6. Transmission and storage overhead

| instance | public key | secret key | ciphertext | shared secret |
|---|---|---|---|---|

## Symmetric primitives

[Survey](../symmetric-survey.md) verdict: **ICCS-only** — pseudohash for G/H; seed expansion via per-seed ICCS DRNG instances; XKCP Keccak dead

Share of each operation spent in the ICCS placeholder hash functions and in the ICCS DRNG (reference build, measured in the same run with link-time wrappers):

| instance | operation | pseudohash/XOF/sm3 | DRNG | calls per operation |
|---|---|---|---|---|

## 7. Raw evidence index

Paths are relative to `performance/data/arm_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

