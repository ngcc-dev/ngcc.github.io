<!-- synchronized from harness: hash-08/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-08</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101539583977672704.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-08.md">arm_1</a></p>

# hash-08 Duet — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Duet
- Implementation versions measured: reference
- Parameter sets: `Duet-512`, `Duet-768`, `Duet-1024`
- Security evaluation: [hash-08 report](../../reports/hash-08.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-08/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Duet-512` | guide | PASS |
| `Duet-768` | guide | PASS |
| `Duet-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Duet-512` | 32 B | 6249 | 195.3 | 2.99 µs | 10.7 | 100000 (5 × 20000) |
| `Duet-512` | 128 B | 18.6 k | 145.2 | 8.88 µs | 14.4 | 100000 (5 × 20000) |
| `Duet-512` | 512 B | 67.8 k | 132.4 | 32.4 µs | 15.8 | 100000 (5 × 20000) |
| `Duet-512` | 1024 B | 135.4 k | 132.2 | 64.7 µs | 15.8 | 69120 (5 × 13824) |
| `Duet-512` | 4096 B | 528.7 k | 129.1 | 253 µs | 16.2 | 19225 (5 × 3845) |
| `Duet-512` | 8192 B | 1.05 M | 128.3 | 502 µs | 16.3 | 9685 (5 × 1937) |
| `Duet-512` | 16384 B | 2.10 M | 128.3 | 1 ms | 16.3 | 4950 (5 × 990) |
| `Duet-512` | 65536 B | 8.40 M | 128.2 | 4.01 ms | 16.3 | 1245 (5 × 249) |
| `Duet-768` | 32 B | 29.4 k | 917.5 | 14 µs | 2.3 | 100000 (5 × 20000) |
| `Duet-768` | 128 B | 29.3 k | 229.3 | 14 µs | 9.1 | 100000 (5 × 20000) |
| `Duet-768` | 512 B | 116.2 k | 226.9 | 55.5 µs | 9.2 | 79405 (5 × 15881) |
| `Duet-768` | 1024 B | 232.3 k | 226.8 | 111 µs | 9.2 | 42275 (5 × 8455) |
| `Duet-768` | 4096 B | 898.9 k | 219.5 | 429 µs | 9.5 | 11680 (5 × 2336) |
| `Duet-768` | 8192 B | 1.77 M | 216.0 | 845 µs | 9.7 | 5860 (5 × 1172) |
| `Duet-768` | 16384 B | 3.51 M | 214.3 | 1.68 ms | 9.8 | 2955 (5 × 591) |
| `Duet-768` | 65536 B | 14.02 M | 213.9 | 6.7 ms | 9.8 | 735 (5 × 147) |
| `Duet-1024` | 32 B | 29.3 k | 916.4 | 14 µs | 2.3 | 100000 (5 × 20000) |
| `Duet-1024` | 128 B | 58.3 k | 455.4 | 27.8 µs | 4.6 | 100000 (5 × 20000) |
| `Duet-1024` | 512 B | 174.4 k | 340.7 | 83.3 µs | 6.1 | 55270 (5 × 11054) |
| `Duet-1024` | 1024 B | 319.4 k | 311.9 | 153 µs | 6.7 | 31395 (5 × 6279) |
| `Duet-1024` | 4096 B | 1.25 M | 304.7 | 596 µs | 6.9 | 8370 (5 × 1674) |
| `Duet-1024` | 8192 B | 2.50 M | 304.7 | 1.19 ms | 6.9 | 4130 (5 × 826) |
| `Duet-1024` | 16384 B | 4.96 M | 303.0 | 2.37 ms | 6.9 | 2100 (5 × 420) |
| `Duet-1024` | 65536 B | 19.85 M | 302.8 | 9.48 ms | 6.9 | 530 (5 × 106) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Duet-512` | hash_32 | 14233 | 1672 KiB | 1780 KiB |
| `Duet-512` | hash_128 | 14233 | 1688 KiB | 1752 KiB |
| `Duet-512` | hash_512 | 14233 | 1692 KiB | 1772 KiB |
| `Duet-512` | hash_1024 | 14233 | 1680 KiB | 1744 KiB |
| `Duet-512` | hash_4096 | 14233 | 1676 KiB | 1768 KiB |
| `Duet-512` | hash_8192 | 14233 | 1704 KiB | 1784 KiB |
| `Duet-512` | hash_16384 | 14233 | 1696 KiB | 1796 KiB |
| `Duet-512` | hash_65536 | 14233 | 1756 KiB | 1844 KiB |
| `Duet-768` | hash_32 | 16089 | 1692 KiB | 1756 KiB |
| `Duet-768` | hash_128 | 16089 | 1692 KiB | 1756 KiB |
| `Duet-768` | hash_512 | 16089 | 1692 KiB | 1756 KiB |
| `Duet-768` | hash_1024 | 16089 | 1676 KiB | 1772 KiB |
| `Duet-768` | hash_4096 | 16089 | 1696 KiB | 1784 KiB |
| `Duet-768` | hash_8192 | 16089 | 1696 KiB | 1760 KiB |
| `Duet-768` | hash_16384 | 16089 | 1708 KiB | 1772 KiB |
| `Duet-768` | hash_65536 | 16089 | 1752 KiB | 1816 KiB |
| `Duet-1024` | hash_32 | 15777 | 1684 KiB | 1748 KiB |
| `Duet-1024` | hash_128 | 15777 | 1676 KiB | 1780 KiB |
| `Duet-1024` | hash_512 | 15777 | 1672 KiB | 1736 KiB |
| `Duet-1024` | hash_1024 | 15777 | 1672 KiB | 1780 KiB |
| `Duet-1024` | hash_4096 | 15777 | 1676 KiB | 1764 KiB |
| `Duet-1024` | hash_8192 | 15777 | 1684 KiB | 1788 KiB |
| `Duet-1024` | hash_16384 | 15777 | 1700 KiB | 1764 KiB |
| `Duet-1024` | hash_65536 | 15777 | 1760 KiB | 1824 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Duet-512` | KAT log (sha256 `b950f02017d1e89d…`) | `kat/hash-08/Duet-512.log` |
| `Duet-512` | timing hash_1024 | `records/hash-08/Duet-512__hash_1024.json` |
| `Duet-512` | timing hash_128 | `records/hash-08/Duet-512__hash_128.json` |
| `Duet-512` | timing hash_16384 | `records/hash-08/Duet-512__hash_16384.json` |
| `Duet-512` | timing hash_32 | `records/hash-08/Duet-512__hash_32.json` |
| `Duet-512` | timing hash_4096 | `records/hash-08/Duet-512__hash_4096.json` |
| `Duet-512` | timing hash_512 | `records/hash-08/Duet-512__hash_512.json` |
| `Duet-512` | timing hash_65536 | `records/hash-08/Duet-512__hash_65536.json` |
| `Duet-512` | timing hash_8192 | `records/hash-08/Duet-512__hash_8192.json` |
| `Duet-768` | KAT log (sha256 `3c5942b4e27ca6f9…`) | `kat/hash-08/Duet-768.log` |
| `Duet-768` | timing hash_1024 | `records/hash-08/Duet-768__hash_1024.json` |
| `Duet-768` | timing hash_128 | `records/hash-08/Duet-768__hash_128.json` |
| `Duet-768` | timing hash_16384 | `records/hash-08/Duet-768__hash_16384.json` |
| `Duet-768` | timing hash_32 | `records/hash-08/Duet-768__hash_32.json` |
| `Duet-768` | timing hash_4096 | `records/hash-08/Duet-768__hash_4096.json` |
| `Duet-768` | timing hash_512 | `records/hash-08/Duet-768__hash_512.json` |
| `Duet-768` | timing hash_65536 | `records/hash-08/Duet-768__hash_65536.json` |
| `Duet-768` | timing hash_8192 | `records/hash-08/Duet-768__hash_8192.json` |
| `Duet-1024` | KAT log (sha256 `8b44e640e677eb62…`) | `kat/hash-08/Duet-1024.log` |
| `Duet-1024` | timing hash_1024 | `records/hash-08/Duet-1024__hash_1024.json` |
| `Duet-1024` | timing hash_128 | `records/hash-08/Duet-1024__hash_128.json` |
| `Duet-1024` | timing hash_16384 | `records/hash-08/Duet-1024__hash_16384.json` |
| `Duet-1024` | timing hash_32 | `records/hash-08/Duet-1024__hash_32.json` |
| `Duet-1024` | timing hash_4096 | `records/hash-08/Duet-1024__hash_4096.json` |
| `Duet-1024` | timing hash_512 | `records/hash-08/Duet-1024__hash_512.json` |
| `Duet-1024` | timing hash_65536 | `records/hash-08/Duet-1024__hash_65536.json` |
| `Duet-1024` | timing hash_8192 | `records/hash-08/Duet-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

