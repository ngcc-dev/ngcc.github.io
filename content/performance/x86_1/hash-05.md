<!-- synchronized from harness: hash-05/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-05</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101540182026702848.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-05.md">arm_1</a></p>

# hash-05 Cryptographic Hash Algorithm uHash — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Cryptographic Hash Algorithm uHash
- Implementation versions measured: reference
- Parameter sets: `uHash-512`, `uHash-768`, `uHash-1024`
- Security evaluation: [hash-05 report](../../reports/hash-05.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-05/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `uHash-512` | guide | PASS |
| `uHash-768` | guide | PASS |
| `uHash-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `uHash-512` | 32 B | 58.0 k | 1811.0 | 27.8 µs | 1.2 | 100000 (5 × 20000) |
| `uHash-512` | 128 B | 115.4 k | 901.9 | 55.2 µs | 2.3 | 75015 (5 × 15003) |
| `uHash-512` | 512 B | 345.0 k | 673.8 | 165 µs | 3.1 | 28385 (5 × 5677) |
| `uHash-512` | 1024 B | 640.8 k | 625.8 | 307 µs | 3.3 | 15900 (5 × 3180) |
| `uHash-512` | 4096 B | 2.48 M | 605.1 | 1.19 ms | 3.4 | 4195 (5 × 839) |
| `uHash-512` | 8192 B | 4.95 M | 604.6 | 2.37 ms | 3.5 | 2110 (5 × 422) |
| `uHash-512` | 16384 B | 9.79 M | 597.6 | 4.69 ms | 3.5 | 1065 (5 × 213) |
| `uHash-512` | 65536 B | 39.38 M | 600.9 | 18.9 ms | 3.5 | 260 (5 × 52) |
| `uHash-768` | 32 B | 86.7 k | 2708.6 | 41.5 µs | 0.8 | 93890 (5 × 18778) |
| `uHash-768` | 128 B | 259.7 k | 2029.2 | 124 µs | 1.0 | 36900 (5 × 7380) |
| `uHash-768` | 512 B | 780.5 k | 1524.5 | 374 µs | 1.4 | 12830 (5 × 2566) |
| `uHash-768` | 1024 B | 1.47 M | 1433.7 | 703 µs | 1.5 | 6875 (5 × 1375) |
| `uHash-768` | 4096 B | 5.60 M | 1368.2 | 2.68 ms | 1.5 | 1850 (5 × 370) |
| `uHash-768` | 8192 B | 11.08 M | 1352.5 | 5.3 ms | 1.5 | 930 (5 × 186) |
| `uHash-768` | 16384 B | 22.20 M | 1355.1 | 10.6 ms | 1.5 | 475 (5 × 95) |
| `uHash-768` | 65536 B | 88.11 M | 1344.5 | 42.2 ms | 1.6 | 120 (5 × 24) |
| `uHash-1024` | 32 B | 230.6 k | 7206.7 | 110 µs | 0.3 | 40115 (5 × 8023) |
| `uHash-1024` | 128 B | 577.8 k | 4514.0 | 277 µs | 0.5 | 17420 (5 × 3484) |
| `uHash-1024` | 512 B | 1.95 M | 3802.5 | 933 µs | 0.5 | 5245 (5 × 1049) |
| `uHash-1024` | 1024 B | 3.78 M | 3691.9 | 1.81 ms | 0.6 | 2735 (5 × 547) |
| `uHash-1024` | 4096 B | 14.89 M | 3635.2 | 7.12 ms | 0.6 | 690 (5 × 138) |
| `uHash-1024` | 8192 B | 29.68 M | 3623.0 | 14.2 ms | 0.6 | 355 (5 × 71) |
| `uHash-1024` | 16384 B | 58.75 M | 3586.0 | 28.1 ms | 0.6 | 180 (5 × 36) |
| `uHash-1024` | 65536 B | 235.53 M | 3593.9 | 113 ms | 0.6 | 100 (5 × 20) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `uHash-512` | hash_32 | 18185 | 1656 KiB | 1784 KiB |
| `uHash-512` | hash_128 | 18185 | 1676 KiB | 1744 KiB |
| `uHash-512` | hash_512 | 18185 | 1684 KiB | 1752 KiB |
| `uHash-512` | hash_1024 | 18185 | 1636 KiB | 1768 KiB |
| `uHash-512` | hash_4096 | 18185 | 1696 KiB | 1776 KiB |
| `uHash-512` | hash_8192 | 18185 | 1692 KiB | 1768 KiB |
| `uHash-512` | hash_16384 | 18185 | 1692 KiB | 1776 KiB |
| `uHash-512` | hash_65536 | 18185 | 1740 KiB | 1872 KiB |
| `uHash-768` | hash_32 | 18185 | 1684 KiB | 1752 KiB |
| `uHash-768` | hash_128 | 18185 | 1676 KiB | 1776 KiB |
| `uHash-768` | hash_512 | 18185 | 1680 KiB | 1776 KiB |
| `uHash-768` | hash_1024 | 18185 | 1660 KiB | 1788 KiB |
| `uHash-768` | hash_4096 | 18185 | 1696 KiB | 1792 KiB |
| `uHash-768` | hash_8192 | 18185 | 1704 KiB | 1796 KiB |
| `uHash-768` | hash_16384 | 18185 | 1704 KiB | 1816 KiB |
| `uHash-768` | hash_65536 | 18185 | 1756 KiB | 1888 KiB |
| `uHash-1024` | hash_32 | 18185 | 1696 KiB | 1764 KiB |
| `uHash-1024` | hash_128 | 18185 | 1692 KiB | 1788 KiB |
| `uHash-1024` | hash_512 | 18185 | 1692 KiB | 1760 KiB |
| `uHash-1024` | hash_1024 | 18185 | 1676 KiB | 1748 KiB |
| `uHash-1024` | hash_4096 | 18185 | 1696 KiB | 1792 KiB |
| `uHash-1024` | hash_8192 | 18185 | 1680 KiB | 1756 KiB |
| `uHash-1024` | hash_16384 | 18185 | 1664 KiB | 1812 KiB |
| `uHash-1024` | hash_65536 | 18185 | 1756 KiB | 1888 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `uHash-512` | KAT log (sha256 `0029d0290ec4374f…`) | `kat/hash-05/uHash-512.log` |
| `uHash-512` | timing hash_1024 | `records/hash-05/uHash-512__hash_1024.json` |
| `uHash-512` | timing hash_128 | `records/hash-05/uHash-512__hash_128.json` |
| `uHash-512` | timing hash_16384 | `records/hash-05/uHash-512__hash_16384.json` |
| `uHash-512` | timing hash_32 | `records/hash-05/uHash-512__hash_32.json` |
| `uHash-512` | timing hash_4096 | `records/hash-05/uHash-512__hash_4096.json` |
| `uHash-512` | timing hash_512 | `records/hash-05/uHash-512__hash_512.json` |
| `uHash-512` | timing hash_65536 | `records/hash-05/uHash-512__hash_65536.json` |
| `uHash-512` | timing hash_8192 | `records/hash-05/uHash-512__hash_8192.json` |
| `uHash-768` | KAT log (sha256 `ca7d3dd2f9c4a2a5…`) | `kat/hash-05/uHash-768.log` |
| `uHash-768` | timing hash_1024 | `records/hash-05/uHash-768__hash_1024.json` |
| `uHash-768` | timing hash_128 | `records/hash-05/uHash-768__hash_128.json` |
| `uHash-768` | timing hash_16384 | `records/hash-05/uHash-768__hash_16384.json` |
| `uHash-768` | timing hash_32 | `records/hash-05/uHash-768__hash_32.json` |
| `uHash-768` | timing hash_4096 | `records/hash-05/uHash-768__hash_4096.json` |
| `uHash-768` | timing hash_512 | `records/hash-05/uHash-768__hash_512.json` |
| `uHash-768` | timing hash_65536 | `records/hash-05/uHash-768__hash_65536.json` |
| `uHash-768` | timing hash_8192 | `records/hash-05/uHash-768__hash_8192.json` |
| `uHash-1024` | KAT log (sha256 `375d84ad7f410321…`) | `kat/hash-05/uHash-1024.log` |
| `uHash-1024` | timing hash_1024 | `records/hash-05/uHash-1024__hash_1024.json` |
| `uHash-1024` | timing hash_128 | `records/hash-05/uHash-1024__hash_128.json` |
| `uHash-1024` | timing hash_16384 | `records/hash-05/uHash-1024__hash_16384.json` |
| `uHash-1024` | timing hash_32 | `records/hash-05/uHash-1024__hash_32.json` |
| `uHash-1024` | timing hash_4096 | `records/hash-05/uHash-1024__hash_4096.json` |
| `uHash-1024` | timing hash_512 | `records/hash-05/uHash-1024__hash_512.json` |
| `uHash-1024` | timing hash_65536 | `records/hash-05/uHash-1024__hash_65536.json` |
| `uHash-1024` | timing hash_8192 | `records/hash-05/uHash-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

