<!-- synchronized from harness: hash-23/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-23</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101536372126470144.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-23.md">arm_1</a></p>

# hash-23 QILIN — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: QILIN
- Implementation versions measured: reference
- Parameter sets: `QILIN-512`, `QILIN-768`, `QILIN-1024`
- Security evaluation: [hash-23 report](../../reports/hash-23.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-23/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `QILIN-512` | guide | PASS |
| `QILIN-768` | guide | PASS |
| `QILIN-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `QILIN-512` | 32 B | 12.7 k | 396.9 | 6.07 µs | 5.3 | 100000 (5 × 20000) |
| `QILIN-512` | 128 B | 12.7 k | 99.0 | 6.06 µs | 21.1 | 100000 (5 × 20000) |
| `QILIN-512` | 512 B | 25.2 k | 49.3 | 12.1 µs | 42.5 | 100000 (5 × 20000) |
| `QILIN-512` | 1024 B | 50.3 k | 49.1 | 24 µs | 42.6 | 100000 (5 × 20000) |
| `QILIN-512` | 4096 B | 200.7 k | 49.0 | 95.9 µs | 42.7 | 48605 (5 × 9721) |
| `QILIN-512` | 8192 B | 401.0 k | 49.0 | 192 µs | 42.8 | 25225 (5 × 5045) |
| `QILIN-512` | 16384 B | 788.9 k | 48.2 | 377 µs | 43.5 | 13085 (5 × 2617) |
| `QILIN-512` | 65536 B | 3.12 M | 47.6 | 1.49 ms | 44.0 | 3335 (5 × 667) |
| `QILIN-768` | 32 B | 14.7 k | 459.3 | 7.02 µs | 4.6 | 100000 (5 × 20000) |
| `QILIN-768` | 128 B | 14.7 k | 115.0 | 7.03 µs | 18.2 | 100000 (5 × 20000) |
| `QILIN-768` | 512 B | 43.8 k | 85.5 | 20.9 µs | 24.5 | 100000 (5 × 20000) |
| `QILIN-768` | 1024 B | 87.4 k | 85.4 | 41.8 µs | 24.5 | 100000 (5 × 20000) |
| `QILIN-768` | 4096 B | 305.4 k | 74.6 | 146 µs | 28.1 | 32785 (5 × 6557) |
| `QILIN-768` | 8192 B | 594.7 k | 72.6 | 284 µs | 28.8 | 17245 (5 × 3449) |
| `QILIN-768` | 16384 B | 1.19 M | 72.6 | 570 µs | 28.7 | 8735 (5 × 1747) |
| `QILIN-768` | 65536 B | 4.76 M | 72.7 | 2.27 ms | 28.8 | 2165 (5 × 433) |
| `QILIN-1024` | 32 B | 16.8 k | 523.8 | 8.01 µs | 4.0 | 100000 (5 × 20000) |
| `QILIN-1024` | 128 B | 16.8 k | 131.0 | 8.01 µs | 16.0 | 100000 (5 × 20000) |
| `QILIN-1024` | 512 B | 66.4 k | 129.7 | 31.7 µs | 16.1 | 100000 (5 × 20000) |
| `QILIN-1024` | 1024 B | 132.5 k | 129.4 | 63.3 µs | 16.2 | 70960 (5 × 14192) |
| `QILIN-1024` | 4096 B | 512.7 k | 125.2 | 245 µs | 16.7 | 19930 (5 × 3986) |
| `QILIN-1024` | 8192 B | 1.01 M | 123.1 | 482 µs | 17.0 | 10295 (5 × 2059) |
| `QILIN-1024` | 16384 B | 2.00 M | 122.2 | 956 µs | 17.1 | 5210 (5 × 1042) |
| `QILIN-1024` | 65536 B | 7.96 M | 121.4 | 3.8 ms | 17.2 | 1315 (5 × 263) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `QILIN-512` | hash_32 | 12969 | 1680 KiB | 1744 KiB |
| `QILIN-512` | hash_128 | 12969 | 1688 KiB | 1768 KiB |
| `QILIN-512` | hash_512 | 12969 | 1668 KiB | 1732 KiB |
| `QILIN-512` | hash_1024 | 12969 | 1692 KiB | 1760 KiB |
| `QILIN-512` | hash_4096 | 12969 | 1692 KiB | 1756 KiB |
| `QILIN-512` | hash_8192 | 12969 | 1680 KiB | 1784 KiB |
| `QILIN-512` | hash_16384 | 12969 | 1708 KiB | 1772 KiB |
| `QILIN-512` | hash_65536 | 12969 | 1752 KiB | 1832 KiB |
| `QILIN-768` | hash_32 | 12969 | 1680 KiB | 1776 KiB |
| `QILIN-768` | hash_128 | 12969 | 1664 KiB | 1728 KiB |
| `QILIN-768` | hash_512 | 12969 | 1688 KiB | 1760 KiB |
| `QILIN-768` | hash_1024 | 12969 | 1688 KiB | 1768 KiB |
| `QILIN-768` | hash_4096 | 12969 | 1684 KiB | 1764 KiB |
| `QILIN-768` | hash_8192 | 12969 | 1676 KiB | 1784 KiB |
| `QILIN-768` | hash_16384 | 12969 | 1680 KiB | 1744 KiB |
| `QILIN-768` | hash_65536 | 12969 | 1724 KiB | 1832 KiB |
| `QILIN-1024` | hash_32 | 12985 | 1688 KiB | 1752 KiB |
| `QILIN-1024` | hash_128 | 12985 | 1688 KiB | 1752 KiB |
| `QILIN-1024` | hash_512 | 12985 | 1688 KiB | 1752 KiB |
| `QILIN-1024` | hash_1024 | 12985 | 1680 KiB | 1776 KiB |
| `QILIN-1024` | hash_4096 | 12985 | 1672 KiB | 1784 KiB |
| `QILIN-1024` | hash_8192 | 12985 | 1680 KiB | 1744 KiB |
| `QILIN-1024` | hash_16384 | 12985 | 1708 KiB | 1788 KiB |
| `QILIN-1024` | hash_65536 | 12985 | 1748 KiB | 1828 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `QILIN-512` | KAT log (sha256 `faeff764a4502502…`) | `kat/hash-23/QILIN-512.log` |
| `QILIN-512` | timing hash_1024 | `records/hash-23/QILIN-512__hash_1024.json` |
| `QILIN-512` | timing hash_128 | `records/hash-23/QILIN-512__hash_128.json` |
| `QILIN-512` | timing hash_16384 | `records/hash-23/QILIN-512__hash_16384.json` |
| `QILIN-512` | timing hash_32 | `records/hash-23/QILIN-512__hash_32.json` |
| `QILIN-512` | timing hash_4096 | `records/hash-23/QILIN-512__hash_4096.json` |
| `QILIN-512` | timing hash_512 | `records/hash-23/QILIN-512__hash_512.json` |
| `QILIN-512` | timing hash_65536 | `records/hash-23/QILIN-512__hash_65536.json` |
| `QILIN-512` | timing hash_8192 | `records/hash-23/QILIN-512__hash_8192.json` |
| `QILIN-768` | KAT log (sha256 `84066f7d2a60295e…`) | `kat/hash-23/QILIN-768.log` |
| `QILIN-768` | timing hash_1024 | `records/hash-23/QILIN-768__hash_1024.json` |
| `QILIN-768` | timing hash_128 | `records/hash-23/QILIN-768__hash_128.json` |
| `QILIN-768` | timing hash_16384 | `records/hash-23/QILIN-768__hash_16384.json` |
| `QILIN-768` | timing hash_32 | `records/hash-23/QILIN-768__hash_32.json` |
| `QILIN-768` | timing hash_4096 | `records/hash-23/QILIN-768__hash_4096.json` |
| `QILIN-768` | timing hash_512 | `records/hash-23/QILIN-768__hash_512.json` |
| `QILIN-768` | timing hash_65536 | `records/hash-23/QILIN-768__hash_65536.json` |
| `QILIN-768` | timing hash_8192 | `records/hash-23/QILIN-768__hash_8192.json` |
| `QILIN-1024` | KAT log (sha256 `f66e938297337dcb…`) | `kat/hash-23/QILIN-1024.log` |
| `QILIN-1024` | timing hash_1024 | `records/hash-23/QILIN-1024__hash_1024.json` |
| `QILIN-1024` | timing hash_128 | `records/hash-23/QILIN-1024__hash_128.json` |
| `QILIN-1024` | timing hash_16384 | `records/hash-23/QILIN-1024__hash_16384.json` |
| `QILIN-1024` | timing hash_32 | `records/hash-23/QILIN-1024__hash_32.json` |
| `QILIN-1024` | timing hash_4096 | `records/hash-23/QILIN-1024__hash_4096.json` |
| `QILIN-1024` | timing hash_512 | `records/hash-23/QILIN-1024__hash_512.json` |
| `QILIN-1024` | timing hash_65536 | `records/hash-23/QILIN-1024__hash_65536.json` |
| `QILIN-1024` | timing hash_8192 | `records/hash-23/QILIN-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

