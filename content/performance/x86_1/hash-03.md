<!-- synchronized from harness: hash-03/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-03</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-03.md">arm_1</a></p>

# hash-03 C Hash — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: C Hash
- Implementation versions measured: reference
- Parameter sets: `CHash_512`, `CHash_1024`
- Security evaluation: [hash-03 report](../../reports/hash-03.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101540728942972928.html)

## 2. Assessment environment

| item | value |
|---|---|
| processor | 12th Gen Intel(R) Core(TM) i7-12700 (CPU 2, one core) |
| clock | max 2.10 GHz, governor performance, turbo off, SMT off |
| memory | 31788 MiB |
| OS / kernel | Debian GNU/Linux 13 (trixie) / 6.12.107+deb13-amd64 |
| compiler / build tool | gcc (Debian 14.2.0-19) 14.2.0 / cmake version 3.31.6 |
| campaign start / end (UTC) | 2026-09-25T10:02:21 / 2026-09-28T10:51:21 |

## 3. Functional testing (KAT)

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-03/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `CHash_512` | guide | PASS |
| `CHash_1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `CHash_512` | 32 B | 190.3 k | 5948.3 | 90.9 µs | 0.4 | 50315 (5 × 10063) |
| `CHash_512` | 128 B | 190.3 k | 1487.0 | 90.9 µs | 1.4 | 50420 (5 × 10084) |
| `CHash_512` | 512 B | 760.9 k | 1486.1 | 363 µs | 1.4 | 13490 (5 × 2698) |
| `CHash_512` | 1024 B | 1.33 M | 1300.7 | 636 µs | 1.6 | 7630 (5 × 1526) |
| `CHash_512` | 4096 B | 4.47 M | 1092.0 | 2.14 ms | 1.9 | 2275 (5 × 455) |
| `CHash_512` | 8192 B | 8.75 M | 1068.4 | 4.18 ms | 2.0 | 1190 (5 × 238) |
| `CHash_512` | 16384 B | 17.22 M | 1050.9 | 8.23 ms | 2.0 | 600 (5 × 120) |
| `CHash_512` | 65536 B | 67.98 M | 1037.2 | 32.5 ms | 2.0 | 155 (5 × 31) |
| `CHash_1024` | 32 B | 190.4 k | 5948.9 | 90.9 µs | 0.4 | 50355 (5 × 10071) |
| `CHash_1024` | 128 B | 190.3 k | 1486.8 | 90.9 µs | 1.4 | 50515 (5 × 10103) |
| `CHash_1024` | 512 B | 762.8 k | 1489.9 | 364 µs | 1.4 | 13380 (5 × 2676) |
| `CHash_1024` | 1024 B | 1.33 M | 1303.7 | 638 µs | 1.6 | 7695 (5 × 1539) |
| `CHash_1024` | 4096 B | 4.48 M | 1094.0 | 2.14 ms | 1.9 | 2325 (5 × 465) |
| `CHash_1024` | 8192 B | 8.77 M | 1070.8 | 4.19 ms | 2.0 | 1185 (5 × 237) |
| `CHash_1024` | 16384 B | 17.26 M | 1053.3 | 8.24 ms | 2.0 | 600 (5 × 120) |
| `CHash_1024` | 65536 B | 68.14 M | 1039.8 | 32.5 ms | 2.0 | 155 (5 × 31) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `CHash_512` | hash_32 | 17281 | 1676 KiB | 1772 KiB |
| `CHash_512` | hash_128 | 17281 | 1696 KiB | 1764 KiB |
| `CHash_512` | hash_512 | 17281 | 1676 KiB | 1764 KiB |
| `CHash_512` | hash_1024 | 17281 | 1632 KiB | 1764 KiB |
| `CHash_512` | hash_4096 | 17281 | 1688 KiB | 1772 KiB |
| `CHash_512` | hash_8192 | 17281 | 1692 KiB | 1788 KiB |
| `CHash_512` | hash_16384 | 17281 | 1708 KiB | 1808 KiB |
| `CHash_512` | hash_65536 | 17281 | 1740 KiB | 1908 KiB |
| `CHash_1024` | hash_32 | 17281 | 1696 KiB | 1760 KiB |
| `CHash_1024` | hash_128 | 17281 | 1672 KiB | 1736 KiB |
| `CHash_1024` | hash_512 | 17281 | 1672 KiB | 1736 KiB |
| `CHash_1024` | hash_1024 | 17281 | 1632 KiB | 1764 KiB |
| `CHash_1024` | hash_4096 | 17281 | 1692 KiB | 1760 KiB |
| `CHash_1024` | hash_8192 | 17281 | 1684 KiB | 1776 KiB |
| `CHash_1024` | hash_16384 | 17281 | 1708 KiB | 1788 KiB |
| `CHash_1024` | hash_65536 | 17281 | 1728 KiB | 1912 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `CHash_512` | KAT log (sha256 `0b6ad2a61e56cc4a…`) | `kat/hash-03/CHash_512.log` |
| `CHash_512` | timing hash_1024 | `records/hash-03/CHash_512__hash_1024.json` |
| `CHash_512` | timing hash_128 | `records/hash-03/CHash_512__hash_128.json` |
| `CHash_512` | timing hash_16384 | `records/hash-03/CHash_512__hash_16384.json` |
| `CHash_512` | timing hash_32 | `records/hash-03/CHash_512__hash_32.json` |
| `CHash_512` | timing hash_4096 | `records/hash-03/CHash_512__hash_4096.json` |
| `CHash_512` | timing hash_512 | `records/hash-03/CHash_512__hash_512.json` |
| `CHash_512` | timing hash_65536 | `records/hash-03/CHash_512__hash_65536.json` |
| `CHash_512` | timing hash_8192 | `records/hash-03/CHash_512__hash_8192.json` |
| `CHash_1024` | KAT log (sha256 `9ec6ff5572945684…`) | `kat/hash-03/CHash_1024.log` |
| `CHash_1024` | timing hash_1024 | `records/hash-03/CHash_1024__hash_1024.json` |
| `CHash_1024` | timing hash_128 | `records/hash-03/CHash_1024__hash_128.json` |
| `CHash_1024` | timing hash_16384 | `records/hash-03/CHash_1024__hash_16384.json` |
| `CHash_1024` | timing hash_32 | `records/hash-03/CHash_1024__hash_32.json` |
| `CHash_1024` | timing hash_4096 | `records/hash-03/CHash_1024__hash_4096.json` |
| `CHash_1024` | timing hash_512 | `records/hash-03/CHash_1024__hash_512.json` |
| `CHash_1024` | timing hash_65536 | `records/hash-03/CHash_1024__hash_65536.json` |
| `CHash_1024` | timing hash_8192 | `records/hash-03/CHash_1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

