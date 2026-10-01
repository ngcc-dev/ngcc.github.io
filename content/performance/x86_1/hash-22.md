<!-- synchronized from harness: hash-22/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-22</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101536571221692416.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-22.md">arm_1</a></p>

# hash-22 Pavelor: A Highly Secure Hash Algorithm for Software Implementation — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Pavelor: A Highly Secure Hash Algorithm for Software Implementation
- Implementation versions measured: reference
- Parameter sets: `Pavelor-512`, `Pavelor-768`, `Pavelor-1024`
- Security evaluation: [hash-22 report](../../reports/hash-22.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-22/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Pavelor-512` | guide | PASS |
| `Pavelor-768` | guide | PASS |
| `Pavelor-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Pavelor-512` | 32 B | 37.8 k | 1180.9 | 18.1 µs | 1.8 | 100000 (5 × 20000) |
| `Pavelor-512` | 128 B | 40.6 k | 317.0 | 19.4 µs | 6.6 | 100000 (5 × 20000) |
| `Pavelor-512` | 512 B | 114.5 k | 223.6 | 54.7 µs | 9.4 | 72135 (5 × 14427) |
| `Pavelor-512` | 1024 B | 224.0 k | 218.8 | 107 µs | 9.6 | 42575 (5 × 8515) |
| `Pavelor-512` | 4096 B | 816.4 k | 199.3 | 390 µs | 10.5 | 12530 (5 × 2506) |
| `Pavelor-512` | 8192 B | 1.60 M | 194.9 | 763 µs | 10.7 | 6445 (5 × 1289) |
| `Pavelor-512` | 16384 B | 3.19 M | 194.5 | 1.52 ms | 10.8 | 3260 (5 × 652) |
| `Pavelor-512` | 65536 B | 12.64 M | 192.9 | 6.04 ms | 10.9 | 830 (5 × 166) |
| `Pavelor-768` | 32 B | 37.9 k | 1183.4 | 18.1 µs | 1.8 | 100000 (5 × 20000) |
| `Pavelor-768` | 128 B | 73.8 k | 576.3 | 35.2 µs | 3.6 | 100000 (5 × 20000) |
| `Pavelor-768` | 512 B | 184.4 k | 360.2 | 88.1 µs | 5.8 | 52450 (5 × 10490) |
| `Pavelor-768` | 1024 B | 332.7 k | 324.9 | 159 µs | 6.4 | 30195 (5 × 6039) |
| `Pavelor-768` | 4096 B | 1.22 M | 297.9 | 583 µs | 7.0 | 8500 (5 × 1700) |
| `Pavelor-768` | 8192 B | 2.40 M | 293.5 | 1.15 ms | 7.1 | 4330 (5 × 866) |
| `Pavelor-768` | 16384 B | 4.76 M | 290.5 | 2.28 ms | 7.2 | 2195 (5 × 439) |
| `Pavelor-768` | 65536 B | 19.02 M | 290.2 | 9.08 ms | 7.2 | 550 (5 × 110) |
| `Pavelor-1024` | 32 B | 74.5 k | 2329.1 | 35.6 µs | 0.9 | 100000 (5 × 20000) |
| `Pavelor-1024` | 128 B | 147.3 k | 1150.7 | 70.7 µs | 1.8 | 64550 (5 × 12910) |
| `Pavelor-1024` | 512 B | 369.3 k | 721.2 | 176 µs | 2.9 | 27355 (5 × 5471) |
| `Pavelor-1024` | 1024 B | 662.8 k | 647.2 | 317 µs | 3.2 | 15480 (5 × 3096) |
| `Pavelor-1024` | 4096 B | 2.44 M | 594.7 | 1.16 ms | 3.5 | 4260 (5 × 852) |
| `Pavelor-1024` | 8192 B | 4.80 M | 585.7 | 2.29 ms | 3.6 | 2175 (5 × 435) |
| `Pavelor-1024` | 16384 B | 9.50 M | 579.8 | 4.54 ms | 3.6 | 1090 (5 × 218) |
| `Pavelor-1024` | 65536 B | 37.78 M | 576.5 | 18 ms | 3.6 | 280 (5 × 56) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Pavelor-512` | hash_32 | 15905 | 1664 KiB | 1772 KiB |
| `Pavelor-512` | hash_128 | 15905 | 1676 KiB | 1772 KiB |
| `Pavelor-512` | hash_512 | 15905 | 1668 KiB | 1776 KiB |
| `Pavelor-512` | hash_1024 | 15905 | 1680 KiB | 1760 KiB |
| `Pavelor-512` | hash_4096 | 15905 | 1680 KiB | 1744 KiB |
| `Pavelor-512` | hash_8192 | 15905 | 1692 KiB | 1756 KiB |
| `Pavelor-512` | hash_16384 | 15905 | 1704 KiB | 1796 KiB |
| `Pavelor-512` | hash_65536 | 15905 | 1756 KiB | 1824 KiB |
| `Pavelor-768` | hash_32 | 15905 | 1696 KiB | 1784 KiB |
| `Pavelor-768` | hash_128 | 15905 | 1668 KiB | 1780 KiB |
| `Pavelor-768` | hash_512 | 15905 | 1636 KiB | 1764 KiB |
| `Pavelor-768` | hash_1024 | 15905 | 1688 KiB | 1772 KiB |
| `Pavelor-768` | hash_4096 | 15905 | 1672 KiB | 1788 KiB |
| `Pavelor-768` | hash_8192 | 15905 | 1676 KiB | 1792 KiB |
| `Pavelor-768` | hash_16384 | 15905 | 1692 KiB | 1776 KiB |
| `Pavelor-768` | hash_65536 | 15905 | 1756 KiB | 1828 KiB |
| `Pavelor-1024` | hash_32 | 15913 | 1684 KiB | 1772 KiB |
| `Pavelor-1024` | hash_128 | 15913 | 1676 KiB | 1780 KiB |
| `Pavelor-1024` | hash_512 | 15913 | 1688 KiB | 1772 KiB |
| `Pavelor-1024` | hash_1024 | 15913 | 1684 KiB | 1776 KiB |
| `Pavelor-1024` | hash_4096 | 15913 | 1688 KiB | 1764 KiB |
| `Pavelor-1024` | hash_8192 | 15913 | 1700 KiB | 1788 KiB |
| `Pavelor-1024` | hash_16384 | 15913 | 1704 KiB | 1796 KiB |
| `Pavelor-1024` | hash_65536 | 15913 | 1760 KiB | 1824 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Pavelor-512` | KAT log (sha256 `f46ede9cb33dfcdf…`) | `kat/hash-22/Pavelor-512.log` |
| `Pavelor-512` | timing hash_1024 | `records/hash-22/Pavelor-512__hash_1024.json` |
| `Pavelor-512` | timing hash_128 | `records/hash-22/Pavelor-512__hash_128.json` |
| `Pavelor-512` | timing hash_16384 | `records/hash-22/Pavelor-512__hash_16384.json` |
| `Pavelor-512` | timing hash_32 | `records/hash-22/Pavelor-512__hash_32.json` |
| `Pavelor-512` | timing hash_4096 | `records/hash-22/Pavelor-512__hash_4096.json` |
| `Pavelor-512` | timing hash_512 | `records/hash-22/Pavelor-512__hash_512.json` |
| `Pavelor-512` | timing hash_65536 | `records/hash-22/Pavelor-512__hash_65536.json` |
| `Pavelor-512` | timing hash_8192 | `records/hash-22/Pavelor-512__hash_8192.json` |
| `Pavelor-768` | KAT log (sha256 `d559880c10a414aa…`) | `kat/hash-22/Pavelor-768.log` |
| `Pavelor-768` | timing hash_1024 | `records/hash-22/Pavelor-768__hash_1024.json` |
| `Pavelor-768` | timing hash_128 | `records/hash-22/Pavelor-768__hash_128.json` |
| `Pavelor-768` | timing hash_16384 | `records/hash-22/Pavelor-768__hash_16384.json` |
| `Pavelor-768` | timing hash_32 | `records/hash-22/Pavelor-768__hash_32.json` |
| `Pavelor-768` | timing hash_4096 | `records/hash-22/Pavelor-768__hash_4096.json` |
| `Pavelor-768` | timing hash_512 | `records/hash-22/Pavelor-768__hash_512.json` |
| `Pavelor-768` | timing hash_65536 | `records/hash-22/Pavelor-768__hash_65536.json` |
| `Pavelor-768` | timing hash_8192 | `records/hash-22/Pavelor-768__hash_8192.json` |
| `Pavelor-1024` | KAT log (sha256 `46333481da8603e0…`) | `kat/hash-22/Pavelor-1024.log` |
| `Pavelor-1024` | timing hash_1024 | `records/hash-22/Pavelor-1024__hash_1024.json` |
| `Pavelor-1024` | timing hash_128 | `records/hash-22/Pavelor-1024__hash_128.json` |
| `Pavelor-1024` | timing hash_16384 | `records/hash-22/Pavelor-1024__hash_16384.json` |
| `Pavelor-1024` | timing hash_32 | `records/hash-22/Pavelor-1024__hash_32.json` |
| `Pavelor-1024` | timing hash_4096 | `records/hash-22/Pavelor-1024__hash_4096.json` |
| `Pavelor-1024` | timing hash_512 | `records/hash-22/Pavelor-1024__hash_512.json` |
| `Pavelor-1024` | timing hash_65536 | `records/hash-22/Pavelor-1024__hash_65536.json` |
| `Pavelor-1024` | timing hash_8192 | `records/hash-22/Pavelor-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

