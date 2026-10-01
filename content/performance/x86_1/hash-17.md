<!-- synchronized from harness: hash-17/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-17</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-17.md">arm_1</a></p>

# hash-17 MasterCube — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: MasterCube
- Implementation versions measured: reference
- Parameter sets: `MasterCube-512`, `MasterCube-768`, `MasterCube-1024`
- Security evaluation: [hash-17 report](../../reports/hash-17.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101537586067099648.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-17/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `MasterCube-512` | guide | PASS |
| `MasterCube-768` | guide | PASS |
| `MasterCube-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `MasterCube-512` | 32 B | 15.4 k | 480.4 | 7.36 µs | 4.4 | 100000 (5 × 20000) |
| `MasterCube-512` | 128 B | 24.0 k | 187.6 | 11.5 µs | 11.1 | 100000 (5 × 20000) |
| `MasterCube-512` | 512 B | 47.9 k | 93.5 | 22.9 µs | 22.3 | 100000 (5 × 20000) |
| `MasterCube-512` | 1024 B | 79.0 k | 77.2 | 37.8 µs | 27.1 | 100000 (5 × 20000) |
| `MasterCube-512` | 4096 B | 279.1 k | 68.1 | 134 µs | 30.7 | 35490 (5 × 7098) |
| `MasterCube-512` | 8192 B | 544.4 k | 66.5 | 260 µs | 31.5 | 17890 (5 × 3578) |
| `MasterCube-512` | 16384 B | 1.07 M | 65.2 | 511 µs | 32.1 | 9830 (5 × 1966) |
| `MasterCube-512` | 65536 B | 4.19 M | 64.0 | 2.01 ms | 32.7 | 2420 (5 × 484) |
| `MasterCube-768` | 32 B | 22.9 k | 715.1 | 11 µs | 2.9 | 100000 (5 × 20000) |
| `MasterCube-768` | 128 B | 31.8 k | 248.1 | 15.2 µs | 8.4 | 100000 (5 × 20000) |
| `MasterCube-768` | 512 B | 63.3 k | 123.7 | 30.3 µs | 16.9 | 100000 (5 × 20000) |
| `MasterCube-768` | 1024 B | 109.8 k | 107.2 | 52.5 µs | 19.5 | 82680 (5 × 16536) |
| `MasterCube-768` | 4096 B | 377.7 k | 92.2 | 181 µs | 22.7 | 26705 (5 × 5341) |
| `MasterCube-768` | 8192 B | 740.7 k | 90.4 | 354 µs | 23.1 | 13980 (5 × 2796) |
| `MasterCube-768` | 16384 B | 1.44 M | 88.2 | 691 µs | 23.7 | 6425 (5 × 1285) |
| `MasterCube-768` | 65536 B | 5.69 M | 86.9 | 2.72 ms | 24.1 | 1845 (5 × 369) |
| `MasterCube-1024` | 32 B | 30.6 k | 955.4 | 14.6 µs | 2.2 | 100000 (5 × 20000) |
| `MasterCube-1024` | 128 B | 47.6 k | 372.2 | 22.8 µs | 5.6 | 100000 (5 × 20000) |
| `MasterCube-1024` | 512 B | 101.7 k | 198.6 | 48.6 µs | 10.5 | 87750 (5 × 17550) |
| `MasterCube-1024` | 1024 B | 171.2 k | 167.2 | 81.9 µs | 12.5 | 49815 (5 × 9963) |
| `MasterCube-1024` | 4096 B | 590.3 k | 144.1 | 282 µs | 14.5 | 13700 (5 × 2740) |
| `MasterCube-1024` | 8192 B | 1.15 M | 139.9 | 548 µs | 14.9 | 9045 (5 × 1809) |
| `MasterCube-1024` | 16384 B | 2.26 M | 137.9 | 1.08 ms | 15.2 | 4530 (5 × 906) |
| `MasterCube-1024` | 65536 B | 8.93 M | 136.2 | 4.27 ms | 15.3 | 1165 (5 × 233) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `MasterCube-512` | hash_32 | 19197 | 1680 KiB | 1744 KiB |
| `MasterCube-512` | hash_128 | 19197 | 1688 KiB | 1752 KiB |
| `MasterCube-512` | hash_512 | 19197 | 1688 KiB | 1768 KiB |
| `MasterCube-512` | hash_1024 | 19197 | 1700 KiB | 1784 KiB |
| `MasterCube-512` | hash_4096 | 19197 | 1680 KiB | 1768 KiB |
| `MasterCube-512` | hash_8192 | 19197 | 1680 KiB | 1744 KiB |
| `MasterCube-512` | hash_16384 | 19197 | 1708 KiB | 1800 KiB |
| `MasterCube-512` | hash_65536 | 19197 | 1732 KiB | 1848 KiB |
| `MasterCube-768` | hash_32 | 19277 | 1688 KiB | 1768 KiB |
| `MasterCube-768` | hash_128 | 19277 | 1648 KiB | 1776 KiB |
| `MasterCube-768` | hash_512 | 19277 | 1700 KiB | 1768 KiB |
| `MasterCube-768` | hash_1024 | 19277 | 1664 KiB | 1788 KiB |
| `MasterCube-768` | hash_4096 | 19277 | 1700 KiB | 1788 KiB |
| `MasterCube-768` | hash_8192 | 19277 | 1680 KiB | 1784 KiB |
| `MasterCube-768` | hash_16384 | 19277 | 1696 KiB | 1780 KiB |
| `MasterCube-768` | hash_65536 | 19277 | 1756 KiB | 1820 KiB |
| `MasterCube-1024` | hash_32 | 19273 | 1676 KiB | 1764 KiB |
| `MasterCube-1024` | hash_128 | 19273 | 1680 KiB | 1776 KiB |
| `MasterCube-1024` | hash_512 | 19273 | 1680 KiB | 1776 KiB |
| `MasterCube-1024` | hash_1024 | 19273 | 1692 KiB | 1756 KiB |
| `MasterCube-1024` | hash_4096 | 19273 | 1700 KiB | 1784 KiB |
| `MasterCube-1024` | hash_8192 | 19273 | 1684 KiB | 1748 KiB |
| `MasterCube-1024` | hash_16384 | 19273 | 1688 KiB | 1792 KiB |
| `MasterCube-1024` | hash_65536 | 19273 | 1760 KiB | 1832 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `MasterCube-512` | KAT log (sha256 `0c4c8affbc215d26…`) | `kat/hash-17/MasterCube-512.log` |
| `MasterCube-512` | timing hash_1024 | `records/hash-17/MasterCube-512__hash_1024.json` |
| `MasterCube-512` | timing hash_128 | `records/hash-17/MasterCube-512__hash_128.json` |
| `MasterCube-512` | timing hash_16384 | `records/hash-17/MasterCube-512__hash_16384.json` |
| `MasterCube-512` | timing hash_32 | `records/hash-17/MasterCube-512__hash_32.json` |
| `MasterCube-512` | timing hash_4096 | `records/hash-17/MasterCube-512__hash_4096.json` |
| `MasterCube-512` | timing hash_512 | `records/hash-17/MasterCube-512__hash_512.json` |
| `MasterCube-512` | timing hash_65536 | `records/hash-17/MasterCube-512__hash_65536.json` |
| `MasterCube-512` | timing hash_8192 | `records/hash-17/MasterCube-512__hash_8192.json` |
| `MasterCube-768` | KAT log (sha256 `a28d5271108fcb84…`) | `kat/hash-17/MasterCube-768.log` |
| `MasterCube-768` | timing hash_1024 | `records/hash-17/MasterCube-768__hash_1024.json` |
| `MasterCube-768` | timing hash_128 | `records/hash-17/MasterCube-768__hash_128.json` |
| `MasterCube-768` | timing hash_16384 | `records/hash-17/MasterCube-768__hash_16384.json` |
| `MasterCube-768` | timing hash_32 | `records/hash-17/MasterCube-768__hash_32.json` |
| `MasterCube-768` | timing hash_4096 | `records/hash-17/MasterCube-768__hash_4096.json` |
| `MasterCube-768` | timing hash_512 | `records/hash-17/MasterCube-768__hash_512.json` |
| `MasterCube-768` | timing hash_65536 | `records/hash-17/MasterCube-768__hash_65536.json` |
| `MasterCube-768` | timing hash_8192 | `records/hash-17/MasterCube-768__hash_8192.json` |
| `MasterCube-1024` | KAT log (sha256 `5b26023884de899e…`) | `kat/hash-17/MasterCube-1024.log` |
| `MasterCube-1024` | timing hash_1024 | `records/hash-17/MasterCube-1024__hash_1024.json` |
| `MasterCube-1024` | timing hash_128 | `records/hash-17/MasterCube-1024__hash_128.json` |
| `MasterCube-1024` | timing hash_16384 | `records/hash-17/MasterCube-1024__hash_16384.json` |
| `MasterCube-1024` | timing hash_32 | `records/hash-17/MasterCube-1024__hash_32.json` |
| `MasterCube-1024` | timing hash_4096 | `records/hash-17/MasterCube-1024__hash_4096.json` |
| `MasterCube-1024` | timing hash_512 | `records/hash-17/MasterCube-1024__hash_512.json` |
| `MasterCube-1024` | timing hash_65536 | `records/hash-17/MasterCube-1024__hash_65536.json` |
| `MasterCube-1024` | timing hash_8192 | `records/hash-17/MasterCube-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

