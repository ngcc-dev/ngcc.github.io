<!-- synchronized from harness: hash-28/perf_x86_1.md -->
# hash-28 The XRH-1 Hash Function — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-28` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101535400742440960.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-28.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: The XRH-1 Hash Function
- Implementation versions measured: reference
- Parameter sets: `XRH-1-512`, `XRH-1-768`, `XRH-1-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-28/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `XRH-1-512` | guide | PASS |
| `XRH-1-768` | guide | PASS |
| `XRH-1-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `XRH-1-512` | 32 B | 2665 | 83.3 | 1.28 µs | 25.1 | 100000 (5 × 20000) |
| `XRH-1-512` | 128 B | 5161 | 40.3 | 2.47 µs | 51.8 | 100000 (5 × 20000) |
| `XRH-1-512` | 512 B | 15.3 k | 29.8 | 7.3 µs | 70.1 | 100000 (5 × 20000) |
| `XRH-1-512` | 1024 B | 30.4 k | 29.7 | 14.5 µs | 70.6 | 100000 (5 × 20000) |
| `XRH-1-512` | 4096 B | 118.2 k | 28.9 | 56.5 µs | 72.5 | 76960 (5 × 15392) |
| `XRH-1-512` | 8192 B | 236.5 k | 28.9 | 113 µs | 72.5 | 38205 (5 × 7641) |
| `XRH-1-512` | 16384 B | 472.5 k | 28.8 | 226 µs | 72.6 | 21995 (5 × 4399) |
| `XRH-1-512` | 65536 B | 1.88 M | 28.7 | 900 µs | 72.8 | 5140 (5 × 1028) |
| `XRH-1-768` | 32 B | 5073 | 158.5 | 2.43 µs | 13.2 | 100000 (5 × 20000) |
| `XRH-1-768` | 128 B | 10.0 k | 78.5 | 4.8 µs | 26.7 | 100000 (5 × 20000) |
| `XRH-1-768` | 512 B | 27.6 k | 53.9 | 13.2 µs | 38.8 | 100000 (5 × 20000) |
| `XRH-1-768` | 1024 B | 50.4 k | 49.2 | 24.1 µs | 42.6 | 100000 (5 × 20000) |
| `XRH-1-768` | 4096 B | 188.5 k | 46.0 | 90 µs | 45.5 | 47105 (5 × 9421) |
| `XRH-1-768` | 8192 B | 371.9 k | 45.4 | 178 µs | 46.1 | 25380 (5 × 5076) |
| `XRH-1-768` | 16384 B | 742.0 k | 45.3 | 354 µs | 46.2 | 14000 (5 × 2800) |
| `XRH-1-768` | 65536 B | 2.97 M | 45.4 | 1.42 ms | 46.1 | 3315 (5 × 663) |
| `XRH-1-1024` | 32 B | 17.2 k | 538.4 | 8.23 µs | 3.9 | 100000 (5 × 20000) |
| `XRH-1-1024` | 128 B | 27.3 k | 212.9 | 13 µs | 9.8 | 100000 (5 × 20000) |
| `XRH-1-1024` | 512 B | 66.9 k | 130.7 | 32 µs | 16.0 | 100000 (5 × 20000) |
| `XRH-1-1024` | 1024 B | 119.3 k | 116.5 | 57 µs | 18.0 | 75230 (5 × 15046) |
| `XRH-1-1024` | 4096 B | 437.6 k | 106.8 | 209 µs | 19.6 | 23280 (5 × 4656) |
| `XRH-1-1024` | 8192 B | 865.5 k | 105.6 | 414 µs | 19.8 | 12005 (5 × 2401) |
| `XRH-1-1024` | 16384 B | 1.72 M | 105.2 | 823 µs | 19.9 | 6105 (5 × 1221) |
| `XRH-1-1024` | 65536 B | 6.92 M | 105.6 | 3.31 ms | 19.8 | 1505 (5 × 301) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `XRH-1-512` | hash_32 | 16073 | 1676 KiB | 1740 KiB |
| `XRH-1-512` | hash_128 | 16073 | 1656 KiB | 1780 KiB |
| `XRH-1-512` | hash_512 | 16073 | 1696 KiB | 1784 KiB |
| `XRH-1-512` | hash_1024 | 16073 | 1676 KiB | 1740 KiB |
| `XRH-1-512` | hash_4096 | 16073 | 1700 KiB | 1768 KiB |
| `XRH-1-512` | hash_8192 | 16073 | 1692 KiB | 1756 KiB |
| `XRH-1-512` | hash_16384 | 16073 | 1684 KiB | 1780 KiB |
| `XRH-1-512` | hash_65536 | 16073 | 1752 KiB | 1836 KiB |
| `XRH-1-768` | hash_32 | 16073 | 1692 KiB | 1764 KiB |
| `XRH-1-768` | hash_128 | 16073 | 1684 KiB | 1748 KiB |
| `XRH-1-768` | hash_512 | 16073 | 1692 KiB | 1780 KiB |
| `XRH-1-768` | hash_1024 | 16073 | 1664 KiB | 1728 KiB |
| `XRH-1-768` | hash_4096 | 16073 | 1692 KiB | 1764 KiB |
| `XRH-1-768` | hash_8192 | 16073 | 1684 KiB | 1788 KiB |
| `XRH-1-768` | hash_16384 | 16073 | 1660 KiB | 1788 KiB |
| `XRH-1-768` | hash_65536 | 16073 | 1756 KiB | 1820 KiB |
| `XRH-1-1024` | hash_32 | 16073 | 1668 KiB | 1732 KiB |
| `XRH-1-1024` | hash_128 | 16073 | 1664 KiB | 1728 KiB |
| `XRH-1-1024` | hash_512 | 16073 | 1696 KiB | 1776 KiB |
| `XRH-1-1024` | hash_1024 | 16073 | 1692 KiB | 1756 KiB |
| `XRH-1-1024` | hash_4096 | 16073 | 1688 KiB | 1752 KiB |
| `XRH-1-1024` | hash_8192 | 16073 | 1700 KiB | 1768 KiB |
| `XRH-1-1024` | hash_16384 | 16073 | 1708 KiB | 1800 KiB |
| `XRH-1-1024` | hash_65536 | 16073 | 1756 KiB | 1824 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `XRH-1-512` | KAT log (sha256 `d11a301476600cd6…`) | `kat/hash-28/XRH-1-512.log` |
| `XRH-1-512` | timing hash_1024 | `records/hash-28/XRH-1-512__hash_1024.json` |
| `XRH-1-512` | timing hash_128 | `records/hash-28/XRH-1-512__hash_128.json` |
| `XRH-1-512` | timing hash_16384 | `records/hash-28/XRH-1-512__hash_16384.json` |
| `XRH-1-512` | timing hash_32 | `records/hash-28/XRH-1-512__hash_32.json` |
| `XRH-1-512` | timing hash_4096 | `records/hash-28/XRH-1-512__hash_4096.json` |
| `XRH-1-512` | timing hash_512 | `records/hash-28/XRH-1-512__hash_512.json` |
| `XRH-1-512` | timing hash_65536 | `records/hash-28/XRH-1-512__hash_65536.json` |
| `XRH-1-512` | timing hash_8192 | `records/hash-28/XRH-1-512__hash_8192.json` |
| `XRH-1-768` | KAT log (sha256 `69aee3e87be45a15…`) | `kat/hash-28/XRH-1-768.log` |
| `XRH-1-768` | timing hash_1024 | `records/hash-28/XRH-1-768__hash_1024.json` |
| `XRH-1-768` | timing hash_128 | `records/hash-28/XRH-1-768__hash_128.json` |
| `XRH-1-768` | timing hash_16384 | `records/hash-28/XRH-1-768__hash_16384.json` |
| `XRH-1-768` | timing hash_32 | `records/hash-28/XRH-1-768__hash_32.json` |
| `XRH-1-768` | timing hash_4096 | `records/hash-28/XRH-1-768__hash_4096.json` |
| `XRH-1-768` | timing hash_512 | `records/hash-28/XRH-1-768__hash_512.json` |
| `XRH-1-768` | timing hash_65536 | `records/hash-28/XRH-1-768__hash_65536.json` |
| `XRH-1-768` | timing hash_8192 | `records/hash-28/XRH-1-768__hash_8192.json` |
| `XRH-1-1024` | KAT log (sha256 `eb98a2b772bb8550…`) | `kat/hash-28/XRH-1-1024.log` |
| `XRH-1-1024` | timing hash_1024 | `records/hash-28/XRH-1-1024__hash_1024.json` |
| `XRH-1-1024` | timing hash_128 | `records/hash-28/XRH-1-1024__hash_128.json` |
| `XRH-1-1024` | timing hash_16384 | `records/hash-28/XRH-1-1024__hash_16384.json` |
| `XRH-1-1024` | timing hash_32 | `records/hash-28/XRH-1-1024__hash_32.json` |
| `XRH-1-1024` | timing hash_4096 | `records/hash-28/XRH-1-1024__hash_4096.json` |
| `XRH-1-1024` | timing hash_512 | `records/hash-28/XRH-1-1024__hash_512.json` |
| `XRH-1-1024` | timing hash_65536 | `records/hash-28/XRH-1-1024__hash_65536.json` |
| `XRH-1-1024` | timing hash_8192 | `records/hash-28/XRH-1-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

