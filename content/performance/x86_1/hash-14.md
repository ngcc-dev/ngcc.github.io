<!-- synchronized from harness: hash-14/perf_x86_1.md -->
# hash-14 Laurus — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-14` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101538290232020992.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-14.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Laurus
- Implementation versions measured: reference
- Parameter sets: `Laurus-512`, `Laurus-768`, `Laurus-1024`, `Laurus-XOF`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-14/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Laurus-512` | guide | PASS |
| `Laurus-768` | guide | PASS |
| `Laurus-1024` | guide | PASS |
| `Laurus-XOF` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Laurus-512` | 32 B | 4178 | 130.6 | 2 µs | 16.0 | 100000 (5 × 20000) |
| `Laurus-512` | 128 B | 8206 | 64.1 | 4.37 µs | 29.3 | 100000 (5 × 20000) |
| `Laurus-512` | 512 B | 20.7 k | 40.5 | 9.91 µs | 51.7 | 100000 (5 × 20000) |
| `Laurus-512` | 1024 B | 37.3 k | 36.5 | 17.8 µs | 57.4 | 100000 (5 × 20000) |
| `Laurus-512` | 4096 B | 138.1 k | 33.7 | 66 µs | 62.1 | 75045 (5 × 15009) |
| `Laurus-512` | 8192 B | 272.3 k | 33.2 | 130 µs | 63.0 | 38765 (5 × 7753) |
| `Laurus-512` | 16384 B | 540.0 k | 33.0 | 258 µs | 63.5 | 20870 (5 × 4174) |
| `Laurus-512` | 65536 B | 2.15 M | 32.8 | 1.03 ms | 63.9 | 4845 (5 × 969) |
| `Laurus-768` | 32 B | 4068 | 127.1 | 1.95 µs | 16.5 | 100000 (5 × 20000) |
| `Laurus-768` | 128 B | 8162 | 63.8 | 3.9 µs | 32.8 | 100000 (5 × 20000) |
| `Laurus-768` | 512 B | 23.6 k | 46.0 | 11.3 µs | 45.5 | 100000 (5 × 20000) |
| `Laurus-768` | 1024 B | 43.2 k | 42.2 | 20.6 µs | 49.7 | 100000 (5 × 20000) |
| `Laurus-768` | 4096 B | 166.3 k | 40.6 | 79.5 µs | 51.6 | 58890 (5 × 11778) |
| `Laurus-768` | 8192 B | 333.2 k | 40.7 | 159 µs | 51.5 | 30990 (5 × 6198) |
| `Laurus-768` | 16384 B | 657.7 k | 40.1 | 314 µs | 52.2 | 15320 (5 × 3064) |
| `Laurus-768` | 65536 B | 2.63 M | 40.1 | 1.25 ms | 52.2 | 4090 (5 × 818) |
| `Laurus-1024` | 32 B | 4081 | 127.5 | 1.95 µs | 16.4 | 100000 (5 × 20000) |
| `Laurus-1024` | 128 B | 8208 | 64.1 | 3.92 µs | 32.6 | 100000 (5 × 20000) |
| `Laurus-1024` | 512 B | 32.9 k | 64.3 | 15.7 µs | 32.6 | 100000 (5 × 20000) |
| `Laurus-1024` | 1024 B | 66.0 k | 64.5 | 31.6 µs | 32.5 | 100000 (5 × 20000) |
| `Laurus-1024` | 4096 B | 263.8 k | 64.4 | 126 µs | 32.5 | 37540 (5 × 7508) |
| `Laurus-1024` | 8192 B | 530.0 k | 64.7 | 253 µs | 32.4 | 19365 (5 × 3873) |
| `Laurus-1024` | 16384 B | 1.06 M | 64.7 | 506 µs | 32.4 | 9770 (5 × 1954) |
| `Laurus-1024` | 65536 B | 4.25 M | 64.8 | 2.03 ms | 32.3 | 2475 (5 × 495) |
| `Laurus-XOF` | 32 B | 8147 | 254.6 | 3.89 µs | 8.2 | 100000 (5 × 20000) |
| `Laurus-XOF` | 128 B | 12.3 k | 96.0 | 5.87 µs | 21.8 | 100000 (5 × 20000) |
| `Laurus-XOF` | 512 B | 24.5 k | 47.9 | 11.7 µs | 43.7 | 100000 (5 × 20000) |
| `Laurus-XOF` | 1024 B | 41.4 k | 40.4 | 19.8 µs | 51.8 | 100000 (5 × 20000) |
| `Laurus-XOF` | 4096 B | 141.3 k | 34.5 | 67.5 µs | 60.7 | 71885 (5 × 14377) |
| `Laurus-XOF` | 8192 B | 273.5 k | 33.4 | 131 µs | 62.7 | 37640 (5 × 7528) |
| `Laurus-XOF` | 16384 B | 541.7 k | 33.1 | 259 µs | 63.3 | 19155 (5 × 3831) |
| `Laurus-XOF` | 65536 B | 2.15 M | 32.9 | 1.03 ms | 63.7 | 4895 (5 × 979) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Laurus-512` | hash_32 | 16465 | 1656 KiB | 1780 KiB |
| `Laurus-512` | hash_128 | 16465 | 1676 KiB | 1772 KiB |
| `Laurus-512` | hash_512 | 16465 | 1696 KiB | 1772 KiB |
| `Laurus-512` | hash_1024 | 16465 | 1692 KiB | 1756 KiB |
| `Laurus-512` | hash_4096 | 16465 | 1696 KiB | 1760 KiB |
| `Laurus-512` | hash_8192 | 16465 | 1680 KiB | 1768 KiB |
| `Laurus-512` | hash_16384 | 16465 | 1700 KiB | 1764 KiB |
| `Laurus-512` | hash_65536 | 16465 | 1760 KiB | 1828 KiB |
| `Laurus-768` | hash_32 | 14113 | 1656 KiB | 1780 KiB |
| `Laurus-768` | hash_128 | 14113 | 1668 KiB | 1772 KiB |
| `Laurus-768` | hash_512 | 14113 | 1692 KiB | 1772 KiB |
| `Laurus-768` | hash_1024 | 14113 | 1676 KiB | 1772 KiB |
| `Laurus-768` | hash_4096 | 14113 | 1680 KiB | 1744 KiB |
| `Laurus-768` | hash_8192 | 14113 | 1684 KiB | 1788 KiB |
| `Laurus-768` | hash_16384 | 14113 | 1708 KiB | 1780 KiB |
| `Laurus-768` | hash_65536 | 14113 | 1740 KiB | 1844 KiB |
| `Laurus-1024` | hash_32 | 13825 | 1648 KiB | 1776 KiB |
| `Laurus-1024` | hash_128 | 13825 | 1636 KiB | 1764 KiB |
| `Laurus-1024` | hash_512 | 13825 | 1696 KiB | 1772 KiB |
| `Laurus-1024` | hash_1024 | 13825 | 1668 KiB | 1780 KiB |
| `Laurus-1024` | hash_4096 | 13825 | 1648 KiB | 1776 KiB |
| `Laurus-1024` | hash_8192 | 13825 | 1680 KiB | 1780 KiB |
| `Laurus-1024` | hash_16384 | 13825 | 1688 KiB | 1776 KiB |
| `Laurus-1024` | hash_65536 | 13825 | 1732 KiB | 1844 KiB |
| `Laurus-XOF` | hash_32 | 17073 | 1676 KiB | 1772 KiB |
| `Laurus-XOF` | hash_128 | 17073 | 1692 KiB | 1756 KiB |
| `Laurus-XOF` | hash_512 | 17073 | 1668 KiB | 1780 KiB |
| `Laurus-XOF` | hash_1024 | 17073 | 1672 KiB | 1768 KiB |
| `Laurus-XOF` | hash_4096 | 17073 | 1672 KiB | 1780 KiB |
| `Laurus-XOF` | hash_8192 | 17073 | 1700 KiB | 1772 KiB |
| `Laurus-XOF` | hash_16384 | 17073 | 1700 KiB | 1764 KiB |
| `Laurus-XOF` | hash_65536 | 17073 | 1732 KiB | 1848 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Laurus-512` | KAT log (sha256 `70b1cd5b7aa845fd…`) | `kat/hash-14/Laurus-512.log` |
| `Laurus-512` | timing hash_1024 | `records/hash-14/Laurus-512__hash_1024.json` |
| `Laurus-512` | timing hash_128 | `records/hash-14/Laurus-512__hash_128.json` |
| `Laurus-512` | timing hash_16384 | `records/hash-14/Laurus-512__hash_16384.json` |
| `Laurus-512` | timing hash_32 | `records/hash-14/Laurus-512__hash_32.json` |
| `Laurus-512` | timing hash_4096 | `records/hash-14/Laurus-512__hash_4096.json` |
| `Laurus-512` | timing hash_512 | `records/hash-14/Laurus-512__hash_512.json` |
| `Laurus-512` | timing hash_65536 | `records/hash-14/Laurus-512__hash_65536.json` |
| `Laurus-512` | timing hash_8192 | `records/hash-14/Laurus-512__hash_8192.json` |
| `Laurus-768` | KAT log (sha256 `badb1673c58ae3ee…`) | `kat/hash-14/Laurus-768.log` |
| `Laurus-768` | timing hash_1024 | `records/hash-14/Laurus-768__hash_1024.json` |
| `Laurus-768` | timing hash_128 | `records/hash-14/Laurus-768__hash_128.json` |
| `Laurus-768` | timing hash_16384 | `records/hash-14/Laurus-768__hash_16384.json` |
| `Laurus-768` | timing hash_32 | `records/hash-14/Laurus-768__hash_32.json` |
| `Laurus-768` | timing hash_4096 | `records/hash-14/Laurus-768__hash_4096.json` |
| `Laurus-768` | timing hash_512 | `records/hash-14/Laurus-768__hash_512.json` |
| `Laurus-768` | timing hash_65536 | `records/hash-14/Laurus-768__hash_65536.json` |
| `Laurus-768` | timing hash_8192 | `records/hash-14/Laurus-768__hash_8192.json` |
| `Laurus-1024` | KAT log (sha256 `bc87dd6475c502ab…`) | `kat/hash-14/Laurus-1024.log` |
| `Laurus-1024` | timing hash_1024 | `records/hash-14/Laurus-1024__hash_1024.json` |
| `Laurus-1024` | timing hash_128 | `records/hash-14/Laurus-1024__hash_128.json` |
| `Laurus-1024` | timing hash_16384 | `records/hash-14/Laurus-1024__hash_16384.json` |
| `Laurus-1024` | timing hash_32 | `records/hash-14/Laurus-1024__hash_32.json` |
| `Laurus-1024` | timing hash_4096 | `records/hash-14/Laurus-1024__hash_4096.json` |
| `Laurus-1024` | timing hash_512 | `records/hash-14/Laurus-1024__hash_512.json` |
| `Laurus-1024` | timing hash_65536 | `records/hash-14/Laurus-1024__hash_65536.json` |
| `Laurus-1024` | timing hash_8192 | `records/hash-14/Laurus-1024__hash_8192.json` |
| `Laurus-XOF` | KAT log (sha256 `019d6df824030c23…`) | `kat/hash-14/Laurus-XOF.log` |
| `Laurus-XOF` | timing hash_1024 | `records/hash-14/Laurus-XOF__hash_1024.json` |
| `Laurus-XOF` | timing hash_128 | `records/hash-14/Laurus-XOF__hash_128.json` |
| `Laurus-XOF` | timing hash_16384 | `records/hash-14/Laurus-XOF__hash_16384.json` |
| `Laurus-XOF` | timing hash_32 | `records/hash-14/Laurus-XOF__hash_32.json` |
| `Laurus-XOF` | timing hash_4096 | `records/hash-14/Laurus-XOF__hash_4096.json` |
| `Laurus-XOF` | timing hash_512 | `records/hash-14/Laurus-XOF__hash_512.json` |
| `Laurus-XOF` | timing hash_65536 | `records/hash-14/Laurus-XOF__hash_65536.json` |
| `Laurus-XOF` | timing hash_8192 | `records/hash-14/Laurus-XOF__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

