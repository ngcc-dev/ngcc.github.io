<!-- synchronized from harness: hash-24/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-24</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-24.md">arm_1</a></p>

# hash-24 QuantaSylva Hash — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: QuantaSylva Hash
- Implementation versions measured: reference
- Parameter sets: `QSH-512`, `QSH-768`, `QSH-1024`
- Security evaluation: [hash-24 report](../../reports/hash-24.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101536223673274368.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-24/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `QSH-512` | guide | PASS |
| `QSH-768` | guide | PASS |
| `QSH-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `QSH-512` | 32 B | 81.8 k | 2556.3 | 39.1 µs | 0.8 | 100000 (5 × 20000) |
| `QSH-512` | 128 B | 109.4 k | 854.9 | 52.3 µs | 2.4 | 82070 (5 × 16414) |
| `QSH-512` | 512 B | 190.2 k | 371.5 | 90.9 µs | 5.6 | 50320 (5 × 10064) |
| `QSH-512` | 1024 B | 299.6 k | 292.6 | 143 µs | 7.2 | 32865 (5 × 6573) |
| `QSH-512` | 4096 B | 1.06 M | 258.7 | 506 µs | 8.1 | 9800 (5 × 1960) |
| `QSH-512` | 8192 B | 2.04 M | 249.0 | 975 µs | 8.4 | 5095 (5 × 1019) |
| `QSH-512` | 16384 B | 4.00 M | 244.0 | 1.91 ms | 8.6 | 2615 (5 × 523) |
| `QSH-512` | 65536 B | 15.73 M | 240.0 | 7.51 ms | 8.7 | 660 (5 × 132) |
| `QSH-768` | 32 B | 160.5 k | 5016.4 | 76.7 µs | 0.4 | 59110 (5 × 11822) |
| `QSH-768` | 128 B | 160.7 k | 1255.6 | 76.8 µs | 1.7 | 59390 (5 × 11878) |
| `QSH-768` | 512 B | 267.3 k | 522.0 | 128 µs | 4.0 | 36220 (5 × 7244) |
| `QSH-768` | 1024 B | 375.3 k | 366.5 | 179 µs | 5.7 | 26500 (5 × 5300) |
| `QSH-768` | 4096 B | 1.12 M | 274.1 | 536 µs | 7.6 | 9125 (5 × 1825) |
| `QSH-768` | 8192 B | 2.08 M | 254.1 | 995 µs | 8.2 | 5005 (5 × 1001) |
| `QSH-768` | 16384 B | 4.00 M | 244.2 | 1.91 ms | 8.6 | 2610 (5 × 522) |
| `QSH-768` | 65536 B | 15.55 M | 237.3 | 7.43 ms | 8.8 | 665 (5 × 133) |
| `QSH-1024` | 32 B | 160.3 k | 5010.1 | 76.6 µs | 0.4 | 52655 (5 × 10531) |
| `QSH-1024` | 128 B | 160.3 k | 1252.7 | 76.6 µs | 1.7 | 58490 (5 × 11698) |
| `QSH-1024` | 512 B | 266.5 k | 520.5 | 127 µs | 4.0 | 35220 (5 × 7044) |
| `QSH-1024` | 1024 B | 374.4 k | 365.7 | 179 µs | 5.7 | 26425 (5 × 5285) |
| `QSH-1024` | 4096 B | 1.12 M | 274.1 | 536 µs | 7.6 | 9175 (5 × 1835) |
| `QSH-1024` | 8192 B | 2.09 M | 254.8 | 997 µs | 8.2 | 4595 (5 × 919) |
| `QSH-1024` | 16384 B | 4.02 M | 245.1 | 1.92 ms | 8.5 | 2565 (5 × 513) |
| `QSH-1024` | 65536 B | 15.54 M | 237.1 | 7.42 ms | 8.8 | 670 (5 × 134) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `QSH-512` | hash_32 | 14401 | 1696 KiB | 1760 KiB |
| `QSH-512` | hash_128 | 14401 | 1660 KiB | 1784 KiB |
| `QSH-512` | hash_512 | 14401 | 1684 KiB | 1764 KiB |
| `QSH-512` | hash_1024 | 14401 | 1692 KiB | 1756 KiB |
| `QSH-512` | hash_4096 | 14401 | 1696 KiB | 1788 KiB |
| `QSH-512` | hash_8192 | 14401 | 1680 KiB | 1748 KiB |
| `QSH-512` | hash_16384 | 14401 | 1692 KiB | 1760 KiB |
| `QSH-512` | hash_65536 | 14401 | 1732 KiB | 1848 KiB |
| `QSH-768` | hash_32 | 14401 | 1680 KiB | 1764 KiB |
| `QSH-768` | hash_128 | 14401 | 1680 KiB | 1780 KiB |
| `QSH-768` | hash_512 | 14401 | 1668 KiB | 1732 KiB |
| `QSH-768` | hash_1024 | 14401 | 1692 KiB | 1780 KiB |
| `QSH-768` | hash_4096 | 14401 | 1676 KiB | 1764 KiB |
| `QSH-768` | hash_8192 | 14401 | 1680 KiB | 1784 KiB |
| `QSH-768` | hash_16384 | 14401 | 1704 KiB | 1800 KiB |
| `QSH-768` | hash_65536 | 14401 | 1736 KiB | 1848 KiB |
| `QSH-1024` | hash_32 | 14401 | 1692 KiB | 1756 KiB |
| `QSH-1024` | hash_128 | 14401 | 1688 KiB | 1780 KiB |
| `QSH-1024` | hash_512 | 14401 | 1680 KiB | 1780 KiB |
| `QSH-1024` | hash_1024 | 14401 | 1656 KiB | 1780 KiB |
| `QSH-1024` | hash_4096 | 14401 | 1700 KiB | 1764 KiB |
| `QSH-1024` | hash_8192 | 14401 | 1700 KiB | 1780 KiB |
| `QSH-1024` | hash_16384 | 14401 | 1692 KiB | 1760 KiB |
| `QSH-1024` | hash_65536 | 14401 | 1712 KiB | 1852 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `QSH-512` | KAT log (sha256 `0de7f2030e7c06b3…`) | `kat/hash-24/QSH-512.log` |
| `QSH-512` | timing hash_1024 | `records/hash-24/QSH-512__hash_1024.json` |
| `QSH-512` | timing hash_128 | `records/hash-24/QSH-512__hash_128.json` |
| `QSH-512` | timing hash_16384 | `records/hash-24/QSH-512__hash_16384.json` |
| `QSH-512` | timing hash_32 | `records/hash-24/QSH-512__hash_32.json` |
| `QSH-512` | timing hash_4096 | `records/hash-24/QSH-512__hash_4096.json` |
| `QSH-512` | timing hash_512 | `records/hash-24/QSH-512__hash_512.json` |
| `QSH-512` | timing hash_65536 | `records/hash-24/QSH-512__hash_65536.json` |
| `QSH-512` | timing hash_8192 | `records/hash-24/QSH-512__hash_8192.json` |
| `QSH-768` | KAT log (sha256 `73746257fe9e66f5…`) | `kat/hash-24/QSH-768.log` |
| `QSH-768` | timing hash_1024 | `records/hash-24/QSH-768__hash_1024.json` |
| `QSH-768` | timing hash_128 | `records/hash-24/QSH-768__hash_128.json` |
| `QSH-768` | timing hash_16384 | `records/hash-24/QSH-768__hash_16384.json` |
| `QSH-768` | timing hash_32 | `records/hash-24/QSH-768__hash_32.json` |
| `QSH-768` | timing hash_4096 | `records/hash-24/QSH-768__hash_4096.json` |
| `QSH-768` | timing hash_512 | `records/hash-24/QSH-768__hash_512.json` |
| `QSH-768` | timing hash_65536 | `records/hash-24/QSH-768__hash_65536.json` |
| `QSH-768` | timing hash_8192 | `records/hash-24/QSH-768__hash_8192.json` |
| `QSH-1024` | KAT log (sha256 `97d6763bea0cc373…`) | `kat/hash-24/QSH-1024.log` |
| `QSH-1024` | timing hash_1024 | `records/hash-24/QSH-1024__hash_1024.json` |
| `QSH-1024` | timing hash_128 | `records/hash-24/QSH-1024__hash_128.json` |
| `QSH-1024` | timing hash_16384 | `records/hash-24/QSH-1024__hash_16384.json` |
| `QSH-1024` | timing hash_32 | `records/hash-24/QSH-1024__hash_32.json` |
| `QSH-1024` | timing hash_4096 | `records/hash-24/QSH-1024__hash_4096.json` |
| `QSH-1024` | timing hash_512 | `records/hash-24/QSH-1024__hash_512.json` |
| `QSH-1024` | timing hash_65536 | `records/hash-24/QSH-1024__hash_65536.json` |
| `QSH-1024` | timing hash_8192 | `records/hash-24/QSH-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

