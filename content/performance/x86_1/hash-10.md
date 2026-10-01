<!-- synchronized from harness: hash-10/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-10</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101539111250251776.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-10.md">arm_1</a></p>

# hash-10 FEILIAN — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: FEILIAN
- Implementation versions measured: reference
- Parameter sets: `FEILIAN512`, `FEILIAN768`, `FEILIAN1024`
- Security evaluation: [hash-10 report](../../reports/hash-10.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-10/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `FEILIAN512` | guide | PASS |
| `FEILIAN768` | guide | PASS |
| `FEILIAN1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `FEILIAN512` | 32 B | 2014 | 62.9 | 964 ns | 33.2 | 100000 (5 × 20000) |
| `FEILIAN512` | 128 B | 2014 | 15.7 | 964 ns | 132.8 | 100000 (5 × 20000) |
| `FEILIAN512` | 512 B | 7664 | 15.0 | 3.66 µs | 139.8 | 100000 (5 × 20000) |
| `FEILIAN512` | 1024 B | 15.1 k | 14.8 | 7.23 µs | 141.7 | 100000 (5 × 20000) |
| `FEILIAN512` | 4096 B | 60.0 k | 14.7 | 28.7 µs | 142.8 | 100000 (5 × 20000) |
| `FEILIAN512` | 8192 B | 119.7 k | 14.6 | 57.2 µs | 143.3 | 73620 (5 × 14724) |
| `FEILIAN512` | 16384 B | 239.1 k | 14.6 | 114 µs | 143.5 | 38920 (5 × 7784) |
| `FEILIAN512` | 65536 B | 962.6 k | 14.7 | 460 µs | 142.5 | 9925 (5 × 1985) |
| `FEILIAN768` | 32 B | 2125 | 66.4 | 1.02 µs | 31.5 | 100000 (5 × 20000) |
| `FEILIAN768` | 128 B | 2128 | 16.6 | 1.02 µs | 125.6 | 100000 (5 × 20000) |
| `FEILIAN768` | 512 B | 7767 | 15.2 | 3.71 µs | 137.9 | 100000 (5 × 20000) |
| `FEILIAN768` | 1024 B | 15.2 k | 14.9 | 7.27 µs | 140.8 | 100000 (5 × 20000) |
| `FEILIAN768` | 4096 B | 60.0 k | 14.7 | 28.7 µs | 142.8 | 100000 (5 × 20000) |
| `FEILIAN768` | 8192 B | 119.7 k | 14.6 | 57.2 µs | 143.3 | 73295 (5 × 14659) |
| `FEILIAN768` | 16384 B | 239.0 k | 14.6 | 114 µs | 143.5 | 38825 (5 × 7765) |
| `FEILIAN768` | 65536 B | 960.4 k | 14.7 | 459 µs | 142.8 | 9995 (5 × 1999) |
| `FEILIAN1024` | 32 B | 2175 | 68.0 | 1.04 µs | 30.7 | 100000 (5 × 20000) |
| `FEILIAN1024` | 128 B | 2179 | 17.0 | 1.04 µs | 122.7 | 100000 (5 × 20000) |
| `FEILIAN1024` | 512 B | 7807 | 15.2 | 3.73 µs | 137.2 | 100000 (5 × 20000) |
| `FEILIAN1024` | 1024 B | 15.3 k | 14.9 | 7.3 µs | 140.3 | 100000 (5 × 20000) |
| `FEILIAN1024` | 4096 B | 60.1 k | 14.7 | 28.7 µs | 142.6 | 100000 (5 × 20000) |
| `FEILIAN1024` | 8192 B | 119.8 k | 14.6 | 57.2 µs | 143.1 | 73070 (5 × 14614) |
| `FEILIAN1024` | 16384 B | 239.4 k | 14.6 | 114 µs | 143.3 | 38865 (5 × 7773) |
| `FEILIAN1024` | 65536 B | 961.1 k | 14.7 | 459 µs | 142.8 | 9945 (5 × 1989) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `FEILIAN512` | hash_32 | 13193 | 1684 KiB | 1768 KiB |
| `FEILIAN512` | hash_128 | 13193 | 1684 KiB | 1760 KiB |
| `FEILIAN512` | hash_512 | 13193 | 1688 KiB | 1752 KiB |
| `FEILIAN512` | hash_1024 | 13193 | 1680 KiB | 1744 KiB |
| `FEILIAN512` | hash_4096 | 13193 | 1692 KiB | 1760 KiB |
| `FEILIAN512` | hash_8192 | 13193 | 1668 KiB | 1792 KiB |
| `FEILIAN512` | hash_16384 | 13193 | 1708 KiB | 1788 KiB |
| `FEILIAN512` | hash_65536 | 13193 | 1716 KiB | 1904 KiB |
| `FEILIAN768` | hash_32 | 13065 | 1668 KiB | 1772 KiB |
| `FEILIAN768` | hash_128 | 13065 | 1688 KiB | 1776 KiB |
| `FEILIAN768` | hash_512 | 13065 | 1692 KiB | 1776 KiB |
| `FEILIAN768` | hash_1024 | 13065 | 1668 KiB | 1776 KiB |
| `FEILIAN768` | hash_4096 | 13065 | 1672 KiB | 1760 KiB |
| `FEILIAN768` | hash_8192 | 13065 | 1696 KiB | 1792 KiB |
| `FEILIAN768` | hash_16384 | 13065 | 1696 KiB | 1776 KiB |
| `FEILIAN768` | hash_65536 | 13065 | 1756 KiB | 1884 KiB |
| `FEILIAN1024` | hash_32 | 13065 | 1684 KiB | 1780 KiB |
| `FEILIAN1024` | hash_128 | 13065 | 1672 KiB | 1736 KiB |
| `FEILIAN1024` | hash_512 | 13065 | 1692 KiB | 1756 KiB |
| `FEILIAN1024` | hash_1024 | 13065 | 1688 KiB | 1772 KiB |
| `FEILIAN1024` | hash_4096 | 13065 | 1696 KiB | 1764 KiB |
| `FEILIAN1024` | hash_8192 | 13065 | 1680 KiB | 1792 KiB |
| `FEILIAN1024` | hash_16384 | 13065 | 1688 KiB | 1808 KiB |
| `FEILIAN1024` | hash_65536 | 13065 | 1728 KiB | 1904 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `FEILIAN512` | KAT log (sha256 `2d1d0ff1de6ea491…`) | `kat/hash-10/FEILIAN512.log` |
| `FEILIAN512` | timing hash_1024 | `records/hash-10/FEILIAN512__hash_1024.json` |
| `FEILIAN512` | timing hash_128 | `records/hash-10/FEILIAN512__hash_128.json` |
| `FEILIAN512` | timing hash_16384 | `records/hash-10/FEILIAN512__hash_16384.json` |
| `FEILIAN512` | timing hash_32 | `records/hash-10/FEILIAN512__hash_32.json` |
| `FEILIAN512` | timing hash_4096 | `records/hash-10/FEILIAN512__hash_4096.json` |
| `FEILIAN512` | timing hash_512 | `records/hash-10/FEILIAN512__hash_512.json` |
| `FEILIAN512` | timing hash_65536 | `records/hash-10/FEILIAN512__hash_65536.json` |
| `FEILIAN512` | timing hash_8192 | `records/hash-10/FEILIAN512__hash_8192.json` |
| `FEILIAN768` | KAT log (sha256 `1fc6b35594914855…`) | `kat/hash-10/FEILIAN768.log` |
| `FEILIAN768` | timing hash_1024 | `records/hash-10/FEILIAN768__hash_1024.json` |
| `FEILIAN768` | timing hash_128 | `records/hash-10/FEILIAN768__hash_128.json` |
| `FEILIAN768` | timing hash_16384 | `records/hash-10/FEILIAN768__hash_16384.json` |
| `FEILIAN768` | timing hash_32 | `records/hash-10/FEILIAN768__hash_32.json` |
| `FEILIAN768` | timing hash_4096 | `records/hash-10/FEILIAN768__hash_4096.json` |
| `FEILIAN768` | timing hash_512 | `records/hash-10/FEILIAN768__hash_512.json` |
| `FEILIAN768` | timing hash_65536 | `records/hash-10/FEILIAN768__hash_65536.json` |
| `FEILIAN768` | timing hash_8192 | `records/hash-10/FEILIAN768__hash_8192.json` |
| `FEILIAN1024` | KAT log (sha256 `a87307ec5c0da125…`) | `kat/hash-10/FEILIAN1024.log` |
| `FEILIAN1024` | timing hash_1024 | `records/hash-10/FEILIAN1024__hash_1024.json` |
| `FEILIAN1024` | timing hash_128 | `records/hash-10/FEILIAN1024__hash_128.json` |
| `FEILIAN1024` | timing hash_16384 | `records/hash-10/FEILIAN1024__hash_16384.json` |
| `FEILIAN1024` | timing hash_32 | `records/hash-10/FEILIAN1024__hash_32.json` |
| `FEILIAN1024` | timing hash_4096 | `records/hash-10/FEILIAN1024__hash_4096.json` |
| `FEILIAN1024` | timing hash_512 | `records/hash-10/FEILIAN1024__hash_512.json` |
| `FEILIAN1024` | timing hash_65536 | `records/hash-10/FEILIAN1024__hash_65536.json` |
| `FEILIAN1024` | timing hash_8192 | `records/hash-10/FEILIAN1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

