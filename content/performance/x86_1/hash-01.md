<!-- synchronized from harness: hash-01/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-01</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-01.md">arm_1</a></p>

# hash-01 AFS-TrEDM — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: AFS-TrEDM
- Implementation versions measured: reference
- Parameter sets: `AFS-TrEDM-512`, `AFS-TrEDM-768`, `AFS-TrEDM-1024`
- Security evaluation: [hash-01 report](../../reports/hash-01.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101541113569038336.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-01/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `AFS-TrEDM-512` | guide | PASS |
| `AFS-TrEDM-768` | guide | PASS |
| `AFS-TrEDM-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `AFS-TrEDM-512` | 32 B | 23.7 k | 741.2 | 11.3 µs | 2.8 | 100000 (5 × 20000) |
| `AFS-TrEDM-512` | 128 B | 47.1 k | 368.0 | 22.5 µs | 5.7 | 100000 (5 × 20000) |
| `AFS-TrEDM-512` | 512 B | 117.8 k | 230.1 | 56.3 µs | 9.1 | 75050 (5 × 15010) |
| `AFS-TrEDM-512` | 1024 B | 212.3 k | 207.4 | 101 µs | 10.1 | 44730 (5 × 8946) |
| `AFS-TrEDM-512` | 4096 B | 777.0 k | 189.7 | 371 µs | 11.0 | 13130 (5 × 2626) |
| `AFS-TrEDM-512` | 8192 B | 1.53 M | 186.6 | 730 µs | 11.2 | 6745 (5 × 1349) |
| `AFS-TrEDM-512` | 16384 B | 3.04 M | 185.6 | 1.45 ms | 11.3 | 3430 (5 × 686) |
| `AFS-TrEDM-512` | 65536 B | 12.08 M | 184.4 | 5.77 ms | 11.4 | 855 (5 × 171) |
| `AFS-TrEDM-768` | 32 B | 39.4 k | 1232.1 | 18.8 µs | 1.7 | 100000 (5 × 20000) |
| `AFS-TrEDM-768` | 128 B | 78.3 k | 612.1 | 37.4 µs | 3.4 | 100000 (5 × 20000) |
| `AFS-TrEDM-768` | 512 B | 235.4 k | 459.7 | 112 µs | 4.6 | 40750 (5 × 8150) |
| `AFS-TrEDM-768` | 1024 B | 431.7 k | 421.6 | 206 µs | 5.0 | 22990 (5 × 4598) |
| `AFS-TrEDM-768` | 4096 B | 1.69 M | 411.4 | 805 µs | 5.1 | 6140 (5 × 1228) |
| `AFS-TrEDM-768` | 8192 B | 3.37 M | 411.5 | 1.61 ms | 5.1 | 3085 (5 × 617) |
| `AFS-TrEDM-768` | 16384 B | 6.69 M | 408.3 | 3.2 ms | 5.1 | 1565 (5 × 313) |
| `AFS-TrEDM-768` | 65536 B | 26.80 M | 408.9 | 12.8 ms | 5.1 | 395 (5 × 79) |
| `AFS-TrEDM-1024` | 32 B | 46.9 k | 1465.3 | 22.4 µs | 1.4 | 100000 (5 × 20000) |
| `AFS-TrEDM-1024` | 128 B | 140.5 k | 1097.5 | 67.1 µs | 1.9 | 65095 (5 × 13019) |
| `AFS-TrEDM-1024` | 512 B | 420.9 k | 822.0 | 201 µs | 2.5 | 23680 (5 × 4736) |
| `AFS-TrEDM-1024` | 1024 B | 795.5 k | 776.8 | 380 µs | 2.7 | 12910 (5 × 2582) |
| `AFS-TrEDM-1024` | 4096 B | 3.03 M | 740.6 | 1.45 ms | 2.8 | 3425 (5 × 685) |
| `AFS-TrEDM-1024` | 8192 B | 6.04 M | 737.3 | 2.89 ms | 2.8 | 1725 (5 × 345) |
| `AFS-TrEDM-1024` | 16384 B | 12.03 M | 734.0 | 5.74 ms | 2.9 | 870 (5 × 174) |
| `AFS-TrEDM-1024` | 65536 B | 48.01 M | 732.6 | 22.9 ms | 2.9 | 220 (5 × 44) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `AFS-TrEDM-512` | hash_32 | 15729 | 1660 KiB | 1784 KiB |
| `AFS-TrEDM-512` | hash_128 | 15729 | 1644 KiB | 1772 KiB |
| `AFS-TrEDM-512` | hash_512 | 15729 | 1696 KiB | 1760 KiB |
| `AFS-TrEDM-512` | hash_1024 | 15729 | 1692 KiB | 1756 KiB |
| `AFS-TrEDM-512` | hash_4096 | 15729 | 1692 KiB | 1764 KiB |
| `AFS-TrEDM-512` | hash_8192 | 15729 | 1704 KiB | 1784 KiB |
| `AFS-TrEDM-512` | hash_16384 | 15729 | 1700 KiB | 1796 KiB |
| `AFS-TrEDM-512` | hash_65536 | 15729 | 1756 KiB | 1844 KiB |
| `AFS-TrEDM-768` | hash_32 | 15729 | 1668 KiB | 1760 KiB |
| `AFS-TrEDM-768` | hash_128 | 15729 | 1664 KiB | 1780 KiB |
| `AFS-TrEDM-768` | hash_512 | 15729 | 1668 KiB | 1732 KiB |
| `AFS-TrEDM-768` | hash_1024 | 15729 | 1696 KiB | 1764 KiB |
| `AFS-TrEDM-768` | hash_4096 | 15729 | 1680 KiB | 1784 KiB |
| `AFS-TrEDM-768` | hash_8192 | 15729 | 1696 KiB | 1760 KiB |
| `AFS-TrEDM-768` | hash_16384 | 15729 | 1688 KiB | 1776 KiB |
| `AFS-TrEDM-768` | hash_65536 | 15729 | 1744 KiB | 1808 KiB |
| `AFS-TrEDM-1024` | hash_32 | 15793 | 1668 KiB | 1732 KiB |
| `AFS-TrEDM-1024` | hash_128 | 15793 | 1672 KiB | 1736 KiB |
| `AFS-TrEDM-1024` | hash_512 | 15793 | 1676 KiB | 1784 KiB |
| `AFS-TrEDM-1024` | hash_1024 | 15793 | 1600 KiB | 1728 KiB |
| `AFS-TrEDM-1024` | hash_4096 | 15793 | 1696 KiB | 1768 KiB |
| `AFS-TrEDM-1024` | hash_8192 | 15793 | 1640 KiB | 1768 KiB |
| `AFS-TrEDM-1024` | hash_16384 | 15793 | 1696 KiB | 1800 KiB |
| `AFS-TrEDM-1024` | hash_65536 | 15793 | 1740 KiB | 1804 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `AFS-TrEDM-512` | KAT log (sha256 `fc40f689e72722fa…`) | `kat/hash-01/AFS-TrEDM-512.log` |
| `AFS-TrEDM-512` | timing hash_1024 | `records/hash-01/AFS-TrEDM-512__hash_1024.json` |
| `AFS-TrEDM-512` | timing hash_128 | `records/hash-01/AFS-TrEDM-512__hash_128.json` |
| `AFS-TrEDM-512` | timing hash_16384 | `records/hash-01/AFS-TrEDM-512__hash_16384.json` |
| `AFS-TrEDM-512` | timing hash_32 | `records/hash-01/AFS-TrEDM-512__hash_32.json` |
| `AFS-TrEDM-512` | timing hash_4096 | `records/hash-01/AFS-TrEDM-512__hash_4096.json` |
| `AFS-TrEDM-512` | timing hash_512 | `records/hash-01/AFS-TrEDM-512__hash_512.json` |
| `AFS-TrEDM-512` | timing hash_65536 | `records/hash-01/AFS-TrEDM-512__hash_65536.json` |
| `AFS-TrEDM-512` | timing hash_8192 | `records/hash-01/AFS-TrEDM-512__hash_8192.json` |
| `AFS-TrEDM-768` | KAT log (sha256 `d1715c767bbf5dd5…`) | `kat/hash-01/AFS-TrEDM-768.log` |
| `AFS-TrEDM-768` | timing hash_1024 | `records/hash-01/AFS-TrEDM-768__hash_1024.json` |
| `AFS-TrEDM-768` | timing hash_128 | `records/hash-01/AFS-TrEDM-768__hash_128.json` |
| `AFS-TrEDM-768` | timing hash_16384 | `records/hash-01/AFS-TrEDM-768__hash_16384.json` |
| `AFS-TrEDM-768` | timing hash_32 | `records/hash-01/AFS-TrEDM-768__hash_32.json` |
| `AFS-TrEDM-768` | timing hash_4096 | `records/hash-01/AFS-TrEDM-768__hash_4096.json` |
| `AFS-TrEDM-768` | timing hash_512 | `records/hash-01/AFS-TrEDM-768__hash_512.json` |
| `AFS-TrEDM-768` | timing hash_65536 | `records/hash-01/AFS-TrEDM-768__hash_65536.json` |
| `AFS-TrEDM-768` | timing hash_8192 | `records/hash-01/AFS-TrEDM-768__hash_8192.json` |
| `AFS-TrEDM-1024` | KAT log (sha256 `cfb8e25e7cdf0f49…`) | `kat/hash-01/AFS-TrEDM-1024.log` |
| `AFS-TrEDM-1024` | timing hash_1024 | `records/hash-01/AFS-TrEDM-1024__hash_1024.json` |
| `AFS-TrEDM-1024` | timing hash_128 | `records/hash-01/AFS-TrEDM-1024__hash_128.json` |
| `AFS-TrEDM-1024` | timing hash_16384 | `records/hash-01/AFS-TrEDM-1024__hash_16384.json` |
| `AFS-TrEDM-1024` | timing hash_32 | `records/hash-01/AFS-TrEDM-1024__hash_32.json` |
| `AFS-TrEDM-1024` | timing hash_4096 | `records/hash-01/AFS-TrEDM-1024__hash_4096.json` |
| `AFS-TrEDM-1024` | timing hash_512 | `records/hash-01/AFS-TrEDM-1024__hash_512.json` |
| `AFS-TrEDM-1024` | timing hash_65536 | `records/hash-01/AFS-TrEDM-1024__hash_65536.json` |
| `AFS-TrEDM-1024` | timing hash_8192 | `records/hash-01/AFS-TrEDM-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

