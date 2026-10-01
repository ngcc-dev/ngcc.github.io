<!-- synchronized from harness: hash-26/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-26</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101535839617634304.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-26.md">arm_1</a></p>

# hash-26 The Hash Function CHIME — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: The Hash Function CHIME
- Implementation versions measured: reference
- Parameter sets: `CHIME-512`, `CHIME-1024`
- Security evaluation: [hash-26 report](../../reports/hash-26.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-26/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `CHIME-512` | guide | PASS |
| `CHIME-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `CHIME-512` | 32 B | 2248 | 70.3 | 1.08 µs | 29.7 | 100000 (5 × 20000) |
| `CHIME-512` | 128 B | 6592 | 51.5 | 3.15 µs | 40.6 | 100000 (5 × 20000) |
| `CHIME-512` | 512 B | 19.7 k | 38.4 | 9.41 µs | 54.4 | 100000 (5 × 20000) |
| `CHIME-512` | 1024 B | 37.2 k | 36.3 | 17.8 µs | 57.6 | 100000 (5 × 20000) |
| `CHIME-512` | 4096 B | 141.4 k | 34.5 | 67.6 µs | 60.6 | 65510 (5 × 13102) |
| `CHIME-512` | 8192 B | 282.7 k | 34.5 | 135 µs | 60.6 | 34380 (5 × 6876) |
| `CHIME-512` | 16384 B | 562.0 k | 34.3 | 269 µs | 61.0 | 17910 (5 × 3582) |
| `CHIME-512` | 65536 B | 2.24 M | 34.2 | 1.07 ms | 61.2 | 4435 (5 × 887) |
| `CHIME-1024` | 32 B | 3030 | 94.7 | 1.45 µs | 22.0 | 100000 (5 × 20000) |
| `CHIME-1024` | 128 B | 8849 | 69.1 | 4.23 µs | 30.3 | 100000 (5 × 20000) |
| `CHIME-1024` | 512 B | 29.2 k | 57.1 | 14 µs | 36.6 | 100000 (5 × 20000) |
| `CHIME-1024` | 1024 B | 55.7 k | 54.4 | 26.6 µs | 38.5 | 100000 (5 × 20000) |
| `CHIME-1024` | 4096 B | 216.0 k | 52.7 | 103 µs | 39.7 | 44990 (5 × 8998) |
| `CHIME-1024` | 8192 B | 429.0 k | 52.4 | 205 µs | 40.0 | 23235 (5 × 4647) |
| `CHIME-1024` | 16384 B | 851.4 k | 52.0 | 407 µs | 40.3 | 11750 (5 × 2350) |
| `CHIME-1024` | 65536 B | 3.42 M | 52.2 | 1.63 ms | 40.1 | 2885 (5 × 577) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `CHIME-512` | hash_32 | 13305 | 1692 KiB | 1776 KiB |
| `CHIME-512` | hash_128 | 13305 | 1684 KiB | 1756 KiB |
| `CHIME-512` | hash_512 | 13305 | 1660 KiB | 1724 KiB |
| `CHIME-512` | hash_1024 | 13305 | 1684 KiB | 1772 KiB |
| `CHIME-512` | hash_4096 | 13305 | 1656 KiB | 1784 KiB |
| `CHIME-512` | hash_8192 | 13305 | 1636 KiB | 1772 KiB |
| `CHIME-512` | hash_16384 | 13305 | 1680 KiB | 1812 KiB |
| `CHIME-512` | hash_65536 | 13305 | 1736 KiB | 1864 KiB |
| `CHIME-1024` | hash_32 | 13889 | 1600 KiB | 1728 KiB |
| `CHIME-1024` | hash_128 | 13889 | 1660 KiB | 1784 KiB |
| `CHIME-1024` | hash_512 | 13889 | 1696 KiB | 1772 KiB |
| `CHIME-1024` | hash_1024 | 13889 | 1680 KiB | 1784 KiB |
| `CHIME-1024` | hash_4096 | 13889 | 1700 KiB | 1792 KiB |
| `CHIME-1024` | hash_8192 | 13889 | 1680 KiB | 1800 KiB |
| `CHIME-1024` | hash_16384 | 13889 | 1684 KiB | 1768 KiB |
| `CHIME-1024` | hash_65536 | 13889 | 1724 KiB | 1920 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `CHIME-512` | KAT log (sha256 `9f75bfe327c886dd…`) | `kat/hash-26/CHIME-512.log` |
| `CHIME-512` | timing hash_1024 | `records/hash-26/CHIME-512__hash_1024.json` |
| `CHIME-512` | timing hash_128 | `records/hash-26/CHIME-512__hash_128.json` |
| `CHIME-512` | timing hash_16384 | `records/hash-26/CHIME-512__hash_16384.json` |
| `CHIME-512` | timing hash_32 | `records/hash-26/CHIME-512__hash_32.json` |
| `CHIME-512` | timing hash_4096 | `records/hash-26/CHIME-512__hash_4096.json` |
| `CHIME-512` | timing hash_512 | `records/hash-26/CHIME-512__hash_512.json` |
| `CHIME-512` | timing hash_65536 | `records/hash-26/CHIME-512__hash_65536.json` |
| `CHIME-512` | timing hash_8192 | `records/hash-26/CHIME-512__hash_8192.json` |
| `CHIME-1024` | KAT log (sha256 `3648493718149414…`) | `kat/hash-26/CHIME-1024.log` |
| `CHIME-1024` | timing hash_1024 | `records/hash-26/CHIME-1024__hash_1024.json` |
| `CHIME-1024` | timing hash_128 | `records/hash-26/CHIME-1024__hash_128.json` |
| `CHIME-1024` | timing hash_16384 | `records/hash-26/CHIME-1024__hash_16384.json` |
| `CHIME-1024` | timing hash_32 | `records/hash-26/CHIME-1024__hash_32.json` |
| `CHIME-1024` | timing hash_4096 | `records/hash-26/CHIME-1024__hash_4096.json` |
| `CHIME-1024` | timing hash_512 | `records/hash-26/CHIME-1024__hash_512.json` |
| `CHIME-1024` | timing hash_65536 | `records/hash-26/CHIME-1024__hash_65536.json` |
| `CHIME-1024` | timing hash_8192 | `records/hash-26/CHIME-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

