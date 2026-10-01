<!-- synchronized from harness: hash-29/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-29</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-29.md">arm_1</a></p>

# hash-29 The XRH-2 Hash Function — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: The XRH-2 Hash Function
- Implementation versions measured: reference
- Parameter sets: `XRH-2-512`, `XRH-2-768`, `XRH-2-1024`
- Security evaluation: [hash-29 report](../../reports/hash-29.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101534893223268352.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-29/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `XRH-2-512` | guide | PASS |
| `XRH-2-768` | guide | PASS |
| `XRH-2-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `XRH-2-512` | 32 B | 2721 | 85.0 | 1.3 µs | 24.6 | 100000 (5 × 20000) |
| `XRH-2-512` | 128 B | 5313 | 41.5 | 2.54 µs | 50.4 | 100000 (5 × 20000) |
| `XRH-2-512` | 512 B | 15.8 k | 30.9 | 7.55 µs | 67.8 | 100000 (5 × 20000) |
| `XRH-2-512` | 1024 B | 31.5 k | 30.8 | 15 µs | 68.1 | 100000 (5 × 20000) |
| `XRH-2-512` | 4096 B | 122.2 k | 29.8 | 58.4 µs | 70.1 | 71985 (5 × 14397) |
| `XRH-2-512` | 8192 B | 244.8 k | 29.9 | 117 µs | 70.0 | 41520 (5 × 8304) |
| `XRH-2-512` | 16384 B | 486.6 k | 29.7 | 232 µs | 70.5 | 22000 (5 × 4400) |
| `XRH-2-512` | 65536 B | 1.95 M | 29.7 | 931 µs | 70.4 | 4920 (5 × 984) |
| `XRH-2-768` | 32 B | 5292 | 165.4 | 2.53 µs | 12.6 | 100000 (5 × 20000) |
| `XRH-2-768` | 128 B | 10.3 k | 80.2 | 4.9 µs | 26.1 | 100000 (5 × 20000) |
| `XRH-2-768` | 512 B | 28.4 k | 55.4 | 13.6 µs | 37.8 | 100000 (5 × 20000) |
| `XRH-2-768` | 1024 B | 51.6 k | 50.4 | 24.7 µs | 41.5 | 100000 (5 × 20000) |
| `XRH-2-768` | 4096 B | 194.3 k | 47.4 | 92.8 µs | 44.1 | 52115 (5 × 10423) |
| `XRH-2-768` | 8192 B | 382.4 k | 46.7 | 183 µs | 44.8 | 26870 (5 × 5374) |
| `XRH-2-768` | 16384 B | 762.0 k | 46.5 | 364 µs | 45.0 | 13140 (5 × 2628) |
| `XRH-2-768` | 65536 B | 3.07 M | 46.8 | 1.46 ms | 44.8 | 3320 (5 × 664) |
| `XRH-2-1024` | 32 B | 17.2 k | 537.9 | 8.22 µs | 3.9 | 100000 (5 × 20000) |
| `XRH-2-1024` | 128 B | 27.1 k | 212.0 | 13 µs | 9.9 | 100000 (5 × 20000) |
| `XRH-2-1024` | 512 B | 66.7 k | 130.2 | 31.9 µs | 16.1 | 100000 (5 × 20000) |
| `XRH-2-1024` | 1024 B | 118.5 k | 115.7 | 56.6 µs | 18.1 | 74565 (5 × 14913) |
| `XRH-2-1024` | 4096 B | 435.4 k | 106.3 | 208 µs | 19.7 | 22295 (5 × 4459) |
| `XRH-2-1024` | 8192 B | 861.5 k | 105.2 | 412 µs | 19.9 | 11495 (5 × 2299) |
| `XRH-2-1024` | 16384 B | 1.73 M | 105.3 | 824 µs | 19.9 | 5830 (5 × 1166) |
| `XRH-2-1024` | 65536 B | 6.92 M | 105.6 | 3.3 ms | 19.8 | 1510 (5 × 302) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `XRH-2-512` | hash_32 | 16073 | 1692 KiB | 1784 KiB |
| `XRH-2-512` | hash_128 | 16073 | 1684 KiB | 1784 KiB |
| `XRH-2-512` | hash_512 | 16073 | 1696 KiB | 1760 KiB |
| `XRH-2-512` | hash_1024 | 16073 | 1688 KiB | 1752 KiB |
| `XRH-2-512` | hash_4096 | 16073 | 1676 KiB | 1784 KiB |
| `XRH-2-512` | hash_8192 | 16073 | 1684 KiB | 1780 KiB |
| `XRH-2-512` | hash_16384 | 16073 | 1692 KiB | 1772 KiB |
| `XRH-2-512` | hash_65536 | 16073 | 1748 KiB | 1812 KiB |
| `XRH-2-768` | hash_32 | 16073 | 1672 KiB | 1736 KiB |
| `XRH-2-768` | hash_128 | 16073 | 1672 KiB | 1736 KiB |
| `XRH-2-768` | hash_512 | 16073 | 1692 KiB | 1756 KiB |
| `XRH-2-768` | hash_1024 | 16073 | 1676 KiB | 1776 KiB |
| `XRH-2-768` | hash_4096 | 16073 | 1668 KiB | 1732 KiB |
| `XRH-2-768` | hash_8192 | 16073 | 1680 KiB | 1744 KiB |
| `XRH-2-768` | hash_16384 | 16073 | 1708 KiB | 1772 KiB |
| `XRH-2-768` | hash_65536 | 16073 | 1744 KiB | 1808 KiB |
| `XRH-2-1024` | hash_32 | 16073 | 1680 KiB | 1772 KiB |
| `XRH-2-1024` | hash_128 | 16073 | 1668 KiB | 1764 KiB |
| `XRH-2-1024` | hash_512 | 16073 | 1672 KiB | 1760 KiB |
| `XRH-2-1024` | hash_1024 | 16073 | 1672 KiB | 1780 KiB |
| `XRH-2-1024` | hash_4096 | 16073 | 1680 KiB | 1788 KiB |
| `XRH-2-1024` | hash_8192 | 16073 | 1684 KiB | 1788 KiB |
| `XRH-2-1024` | hash_16384 | 16073 | 1688 KiB | 1788 KiB |
| `XRH-2-1024` | hash_65536 | 16073 | 1760 KiB | 1824 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `XRH-2-512` | KAT log (sha256 `bbbf3d8ff271ed13…`) | `kat/hash-29/XRH-2-512.log` |
| `XRH-2-512` | timing hash_1024 | `records/hash-29/XRH-2-512__hash_1024.json` |
| `XRH-2-512` | timing hash_128 | `records/hash-29/XRH-2-512__hash_128.json` |
| `XRH-2-512` | timing hash_16384 | `records/hash-29/XRH-2-512__hash_16384.json` |
| `XRH-2-512` | timing hash_32 | `records/hash-29/XRH-2-512__hash_32.json` |
| `XRH-2-512` | timing hash_4096 | `records/hash-29/XRH-2-512__hash_4096.json` |
| `XRH-2-512` | timing hash_512 | `records/hash-29/XRH-2-512__hash_512.json` |
| `XRH-2-512` | timing hash_65536 | `records/hash-29/XRH-2-512__hash_65536.json` |
| `XRH-2-512` | timing hash_8192 | `records/hash-29/XRH-2-512__hash_8192.json` |
| `XRH-2-768` | KAT log (sha256 `513c7418060dd5e4…`) | `kat/hash-29/XRH-2-768.log` |
| `XRH-2-768` | timing hash_1024 | `records/hash-29/XRH-2-768__hash_1024.json` |
| `XRH-2-768` | timing hash_128 | `records/hash-29/XRH-2-768__hash_128.json` |
| `XRH-2-768` | timing hash_16384 | `records/hash-29/XRH-2-768__hash_16384.json` |
| `XRH-2-768` | timing hash_32 | `records/hash-29/XRH-2-768__hash_32.json` |
| `XRH-2-768` | timing hash_4096 | `records/hash-29/XRH-2-768__hash_4096.json` |
| `XRH-2-768` | timing hash_512 | `records/hash-29/XRH-2-768__hash_512.json` |
| `XRH-2-768` | timing hash_65536 | `records/hash-29/XRH-2-768__hash_65536.json` |
| `XRH-2-768` | timing hash_8192 | `records/hash-29/XRH-2-768__hash_8192.json` |
| `XRH-2-1024` | KAT log (sha256 `3f7b5bf707cb0c45…`) | `kat/hash-29/XRH-2-1024.log` |
| `XRH-2-1024` | timing hash_1024 | `records/hash-29/XRH-2-1024__hash_1024.json` |
| `XRH-2-1024` | timing hash_128 | `records/hash-29/XRH-2-1024__hash_128.json` |
| `XRH-2-1024` | timing hash_16384 | `records/hash-29/XRH-2-1024__hash_16384.json` |
| `XRH-2-1024` | timing hash_32 | `records/hash-29/XRH-2-1024__hash_32.json` |
| `XRH-2-1024` | timing hash_4096 | `records/hash-29/XRH-2-1024__hash_4096.json` |
| `XRH-2-1024` | timing hash_512 | `records/hash-29/XRH-2-1024__hash_512.json` |
| `XRH-2-1024` | timing hash_65536 | `records/hash-29/XRH-2-1024__hash_65536.json` |
| `XRH-2-1024` | timing hash_8192 | `records/hash-29/XRH-2-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

