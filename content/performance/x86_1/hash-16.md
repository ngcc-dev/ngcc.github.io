<!-- synchronized from harness: hash-16/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-16</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101537750001471488.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-16.md">arm_1</a></p>

# hash-16 LLH — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: LLH
- Implementation versions measured: reference
- Parameter sets: `LLH-256`, `LLH-512`, `LLH-768`, `LLH-1024`
- Security evaluation: [hash-16 report](../../reports/hash-16.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-16/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `LLH-256` | guide | PASS |
| `LLH-512` | guide | PASS |
| `LLH-768` | guide | PASS |
| `LLH-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `LLH-256` | 32 B | 2006 | 62.7 | 961 ns | 33.3 | 100000 (5 × 20000) |
| `LLH-256` | 128 B | 5098 | 39.8 | 2.44 µs | 52.5 | 100000 (5 × 20000) |
| `LLH-256` | 512 B | 17.8 k | 34.8 | 8.52 µs | 60.1 | 100000 (5 × 20000) |
| `LLH-256` | 1024 B | 34.2 k | 33.4 | 16.4 µs | 62.6 | 100000 (5 × 20000) |
| `LLH-256` | 4096 B | 135.3 k | 33.0 | 64.6 µs | 63.4 | 66225 (5 × 13245) |
| `LLH-256` | 8192 B | 269.3 k | 32.9 | 129 µs | 63.7 | 38045 (5 × 7609) |
| `LLH-256` | 16384 B | 537.8 k | 32.8 | 257 µs | 63.8 | 19510 (5 × 3902) |
| `LLH-256` | 65536 B | 2.14 M | 32.7 | 1.02 ms | 64.1 | 4565 (5 × 913) |
| `LLH-512` | 32 B | 2993 | 93.5 | 1.43 µs | 22.3 | 100000 (5 × 20000) |
| `LLH-512` | 128 B | 4482 | 35.0 | 2.14 µs | 59.7 | 100000 (5 × 20000) |
| `LLH-512` | 512 B | 13.7 k | 26.8 | 6.57 µs | 78.0 | 100000 (5 × 20000) |
| `LLH-512` | 1024 B | 26.4 k | 25.8 | 12.6 µs | 81.2 | 100000 (5 × 20000) |
| `LLH-512` | 4096 B | 102.2 k | 25.0 | 48.8 µs | 83.9 | 72390 (5 × 14478) |
| `LLH-512` | 8192 B | 204.4 k | 25.0 | 97.7 µs | 83.9 | 46055 (5 × 9211) |
| `LLH-512` | 16384 B | 407.6 k | 24.9 | 195 µs | 84.2 | 21215 (5 × 4243) |
| `LLH-512` | 65536 B | 1.62 M | 24.7 | 774 µs | 84.6 | 5770 (5 × 1154) |
| `LLH-768` | 32 B | 10.3 k | 323.1 | 4.94 µs | 6.5 | 100000 (5 × 20000) |
| `LLH-768` | 128 B | 15.5 k | 121.4 | 7.43 µs | 17.2 | 100000 (5 × 20000) |
| `LLH-768` | 512 B | 36.7 k | 71.7 | 17.5 µs | 29.2 | 100000 (5 × 20000) |
| `LLH-768` | 1024 B | 62.3 k | 60.8 | 29.7 µs | 34.4 | 100000 (5 × 20000) |
| `LLH-768` | 4096 B | 231.8 k | 56.6 | 111 µs | 37.0 | 40905 (5 × 8181) |
| `LLH-768` | 8192 B | 459.3 k | 56.1 | 219 µs | 37.3 | 23275 (5 × 4655) |
| `LLH-768` | 16384 B | 914.9 k | 55.8 | 437 µs | 37.5 | 9230 (5 × 1846) |
| `LLH-768` | 65536 B | 3.68 M | 56.2 | 1.76 ms | 37.3 | 3090 (5 × 618) |
| `LLH-1024` | 32 B | 10.3 k | 322.5 | 4.94 µs | 6.5 | 100000 (5 × 20000) |
| `LLH-1024` | 128 B | 10.5 k | 82.0 | 5.03 µs | 25.5 | 100000 (5 × 20000) |
| `LLH-1024` | 512 B | 26.4 k | 51.5 | 12.6 µs | 40.6 | 100000 (5 × 20000) |
| `LLH-1024` | 1024 B | 47.8 k | 46.6 | 22.8 µs | 44.8 | 100000 (5 × 20000) |
| `LLH-1024` | 4096 B | 174.8 k | 42.7 | 83.6 µs | 49.0 | 55505 (5 × 11101) |
| `LLH-1024` | 8192 B | 346.0 k | 42.2 | 166 µs | 49.5 | 29560 (5 × 5912) |
| `LLH-1024` | 16384 B | 685.1 k | 41.8 | 328 µs | 50.0 | 14840 (5 × 2968) |
| `LLH-1024` | 65536 B | 2.74 M | 41.8 | 1.31 ms | 50.0 | 3875 (5 × 775) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `LLH-256` | hash_32 | 12737 | 1692 KiB | 1756 KiB |
| `LLH-256` | hash_128 | 12737 | 1680 KiB | 1744 KiB |
| `LLH-256` | hash_512 | 12737 | 1692 KiB | 1768 KiB |
| `LLH-256` | hash_1024 | 12737 | 1692 KiB | 1768 KiB |
| `LLH-256` | hash_4096 | 12737 | 1680 KiB | 1764 KiB |
| `LLH-256` | hash_8192 | 12737 | 1692 KiB | 1756 KiB |
| `LLH-256` | hash_16384 | 12737 | 1688 KiB | 1752 KiB |
| `LLH-256` | hash_65536 | 12737 | 1752 KiB | 1816 KiB |
| `LLH-512` | hash_32 | 13129 | 1676 KiB | 1768 KiB |
| `LLH-512` | hash_128 | 13129 | 1680 KiB | 1744 KiB |
| `LLH-512` | hash_512 | 13129 | 1656 KiB | 1780 KiB |
| `LLH-512` | hash_1024 | 13129 | 1672 KiB | 1780 KiB |
| `LLH-512` | hash_4096 | 13129 | 1676 KiB | 1740 KiB |
| `LLH-512` | hash_8192 | 13129 | 1672 KiB | 1788 KiB |
| `LLH-512` | hash_16384 | 13129 | 1704 KiB | 1792 KiB |
| `LLH-512` | hash_65536 | 13129 | 1756 KiB | 1824 KiB |
| `LLH-768` | hash_32 | 15497 | 1684 KiB | 1780 KiB |
| `LLH-768` | hash_128 | 15497 | 1668 KiB | 1772 KiB |
| `LLH-768` | hash_512 | 15497 | 1672 KiB | 1780 KiB |
| `LLH-768` | hash_1024 | 15497 | 1692 KiB | 1772 KiB |
| `LLH-768` | hash_4096 | 15497 | 1692 KiB | 1756 KiB |
| `LLH-768` | hash_8192 | 15497 | 1688 KiB | 1780 KiB |
| `LLH-768` | hash_16384 | 15497 | 1688 KiB | 1800 KiB |
| `LLH-768` | hash_65536 | 15497 | 1740 KiB | 1804 KiB |
| `LLH-1024` | hash_32 | 15977 | 1668 KiB | 1776 KiB |
| `LLH-1024` | hash_128 | 15977 | 1688 KiB | 1752 KiB |
| `LLH-1024` | hash_512 | 15977 | 1648 KiB | 1776 KiB |
| `LLH-1024` | hash_1024 | 15977 | 1672 KiB | 1736 KiB |
| `LLH-1024` | hash_4096 | 15977 | 1696 KiB | 1760 KiB |
| `LLH-1024` | hash_8192 | 15977 | 1652 KiB | 1780 KiB |
| `LLH-1024` | hash_16384 | 15977 | 1692 KiB | 1760 KiB |
| `LLH-1024` | hash_65536 | 15977 | 1736 KiB | 1828 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `LLH-256` | KAT log (sha256 `978f6d2cfe261bd0…`) | `kat/hash-16/LLH-256.log` |
| `LLH-256` | timing hash_1024 | `records/hash-16/LLH-256__hash_1024.json` |
| `LLH-256` | timing hash_128 | `records/hash-16/LLH-256__hash_128.json` |
| `LLH-256` | timing hash_16384 | `records/hash-16/LLH-256__hash_16384.json` |
| `LLH-256` | timing hash_32 | `records/hash-16/LLH-256__hash_32.json` |
| `LLH-256` | timing hash_4096 | `records/hash-16/LLH-256__hash_4096.json` |
| `LLH-256` | timing hash_512 | `records/hash-16/LLH-256__hash_512.json` |
| `LLH-256` | timing hash_65536 | `records/hash-16/LLH-256__hash_65536.json` |
| `LLH-256` | timing hash_8192 | `records/hash-16/LLH-256__hash_8192.json` |
| `LLH-512` | KAT log (sha256 `68e4bcb43caea355…`) | `kat/hash-16/LLH-512.log` |
| `LLH-512` | timing hash_1024 | `records/hash-16/LLH-512__hash_1024.json` |
| `LLH-512` | timing hash_128 | `records/hash-16/LLH-512__hash_128.json` |
| `LLH-512` | timing hash_16384 | `records/hash-16/LLH-512__hash_16384.json` |
| `LLH-512` | timing hash_32 | `records/hash-16/LLH-512__hash_32.json` |
| `LLH-512` | timing hash_4096 | `records/hash-16/LLH-512__hash_4096.json` |
| `LLH-512` | timing hash_512 | `records/hash-16/LLH-512__hash_512.json` |
| `LLH-512` | timing hash_65536 | `records/hash-16/LLH-512__hash_65536.json` |
| `LLH-512` | timing hash_8192 | `records/hash-16/LLH-512__hash_8192.json` |
| `LLH-768` | KAT log (sha256 `eceffc3393ccb92f…`) | `kat/hash-16/LLH-768.log` |
| `LLH-768` | timing hash_1024 | `records/hash-16/LLH-768__hash_1024.json` |
| `LLH-768` | timing hash_128 | `records/hash-16/LLH-768__hash_128.json` |
| `LLH-768` | timing hash_16384 | `records/hash-16/LLH-768__hash_16384.json` |
| `LLH-768` | timing hash_32 | `records/hash-16/LLH-768__hash_32.json` |
| `LLH-768` | timing hash_4096 | `records/hash-16/LLH-768__hash_4096.json` |
| `LLH-768` | timing hash_512 | `records/hash-16/LLH-768__hash_512.json` |
| `LLH-768` | timing hash_65536 | `records/hash-16/LLH-768__hash_65536.json` |
| `LLH-768` | timing hash_8192 | `records/hash-16/LLH-768__hash_8192.json` |
| `LLH-1024` | KAT log (sha256 `389f632c0669f0e6…`) | `kat/hash-16/LLH-1024.log` |
| `LLH-1024` | timing hash_1024 | `records/hash-16/LLH-1024__hash_1024.json` |
| `LLH-1024` | timing hash_128 | `records/hash-16/LLH-1024__hash_128.json` |
| `LLH-1024` | timing hash_16384 | `records/hash-16/LLH-1024__hash_16384.json` |
| `LLH-1024` | timing hash_32 | `records/hash-16/LLH-1024__hash_32.json` |
| `LLH-1024` | timing hash_4096 | `records/hash-16/LLH-1024__hash_4096.json` |
| `LLH-1024` | timing hash_512 | `records/hash-16/LLH-1024__hash_512.json` |
| `LLH-1024` | timing hash_65536 | `records/hash-16/LLH-1024__hash_65536.json` |
| `LLH-1024` | timing hash_8192 | `records/hash-16/LLH-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

