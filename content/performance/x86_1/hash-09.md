<!-- synchronized from harness: hash-09/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-09</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101539361927024640.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-09.md">arm_1</a></p>

# hash-09 Eijen Hash Function — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Eijen Hash Function
- Implementation versions measured: reference
- Parameter sets: `Eijen-256`, `Eijen-384`, `Eijen-512`, `Eijen-768`, `Eijen-1024`
- Security evaluation: [hash-09 report](../../reports/hash-09.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-09/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Eijen-256` | guide | PASS |
| `Eijen-384` | guide | PASS |
| `Eijen-512` | guide | PASS |
| `Eijen-768` | guide | PASS |
| `Eijen-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Eijen-256` | 32 B | 2165 | 67.7 | 1.04 µs | 30.8 | 100000 (5 × 20000) |
| `Eijen-256` | 128 B | 2142 | 16.7 | 1.03 µs | 124.7 | 100000 (5 × 20000) |
| `Eijen-256` | 512 B | 6489 | 12.7 | 3.11 µs | 164.9 | 100000 (5 × 20000) |
| `Eijen-256` | 1024 B | 10.4 k | 10.1 | 4.96 µs | 206.4 | 100000 (5 × 20000) |
| `Eijen-256` | 4096 B | 39.3 k | 9.6 | 18.8 µs | 217.9 | 100000 (5 × 20000) |
| `Eijen-256` | 8192 B | 78.0 k | 9.5 | 37.3 µs | 219.6 | 100000 (5 × 20000) |
| `Eijen-256` | 16384 B | 155.7 k | 9.5 | 74.5 µs | 220.0 | 53945 (5 × 10789) |
| `Eijen-256` | 65536 B | 623.2 k | 9.5 | 298 µs | 219.8 | 16600 (5 × 3320) |
| `Eijen-384` | 32 B | 2219 | 69.3 | 1.06 µs | 30.1 | 100000 (5 × 20000) |
| `Eijen-384` | 128 B | 2191 | 17.1 | 1.05 µs | 121.7 | 57540 (5 × 11508) |
| `Eijen-384` | 512 B | 6235 | 12.2 | 2.98 µs | 171.5 | 100000 (5 × 20000) |
| `Eijen-384` | 1024 B | 12.5 k | 12.2 | 5.96 µs | 171.8 | 100000 (5 × 20000) |
| `Eijen-384` | 4096 B | 43.0 k | 10.5 | 20.5 µs | 199.3 | 100000 (5 × 20000) |
| `Eijen-384` | 8192 B | 83.8 k | 10.2 | 40.1 µs | 204.2 | 100000 (5 × 20000) |
| `Eijen-384` | 16384 B | 167.6 k | 10.2 | 80.2 µs | 204.4 | 56620 (5 × 11324) |
| `Eijen-384` | 65536 B | 664.0 k | 10.1 | 318 µs | 206.3 | 14295 (5 × 2859) |
| `Eijen-512` | 32 B | 2150 | 67.2 | 1.03 µs | 31.0 | 100000 (5 × 20000) |
| `Eijen-512` | 128 B | 2192 | 17.1 | 1.05 µs | 121.9 | 100000 (5 × 20000) |
| `Eijen-512` | 512 B | 6446 | 12.6 | 3.08 µs | 166.0 | 100000 (5 × 20000) |
| `Eijen-512` | 1024 B | 12.4 k | 12.1 | 5.95 µs | 172.2 | 100000 (5 × 20000) |
| `Eijen-512` | 4096 B | 47.9 k | 11.7 | 22.9 µs | 178.7 | 100000 (5 × 20000) |
| `Eijen-512` | 8192 B | 94.6 k | 11.5 | 45.2 µs | 181.1 | 97380 (5 × 19476) |
| `Eijen-512` | 16384 B | 186.9 k | 11.4 | 89.4 µs | 183.3 | 46205 (5 × 9241) |
| `Eijen-512` | 65536 B | 735.5 k | 11.2 | 352 µs | 186.3 | 14185 (5 × 2837) |
| `Eijen-768` | 32 B | 2211 | 69.1 | 1.06 µs | 30.2 | 100000 (5 × 20000) |
| `Eijen-768` | 128 B | 2211 | 17.3 | 1.06 µs | 120.9 | 100000 (5 × 20000) |
| `Eijen-768` | 512 B | 8452 | 16.5 | 4.05 µs | 126.6 | 100000 (5 × 20000) |
| `Eijen-768` | 1024 B | 14.8 k | 14.4 | 7.06 µs | 145.1 | 100000 (5 × 20000) |
| `Eijen-768` | 4096 B | 57.7 k | 14.1 | 27.6 µs | 148.4 | 100000 (5 × 20000) |
| `Eijen-768` | 8192 B | 113.1 k | 13.8 | 54.1 µs | 151.4 | 84700 (5 × 16940) |
| `Eijen-768` | 16384 B | 222.0 k | 13.6 | 106 µs | 154.3 | 44140 (5 × 8828) |
| `Eijen-768` | 65536 B | 892.5 k | 13.6 | 427 µs | 153.5 | 11285 (5 × 2257) |
| `Eijen-1024` | 32 B | 2185 | 68.3 | 1.05 µs | 30.5 | 100000 (5 × 20000) |
| `Eijen-1024` | 128 B | 4248 | 33.2 | 2.04 µs | 62.9 | 100000 (5 × 20000) |
| `Eijen-1024` | 512 B | 10.4 k | 20.4 | 4.99 µs | 102.6 | 100000 (5 × 20000) |
| `Eijen-1024` | 1024 B | 19.3 k | 18.9 | 9.23 µs | 110.9 | 100000 (5 × 20000) |
| `Eijen-1024` | 4096 B | 73.4 k | 17.9 | 35.1 µs | 116.7 | 100000 (5 × 20000) |
| `Eijen-1024` | 8192 B | 141.7 k | 17.3 | 67.8 µs | 120.8 | 59480 (5 × 11896) |
| `Eijen-1024` | 16384 B | 282.0 k | 17.2 | 135 µs | 121.4 | 35620 (5 × 7124) |
| `Eijen-1024` | 65536 B | 1.12 M | 17.1 | 537 µs | 122.0 | 9155 (5 × 1831) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Eijen-256` | hash_32 | 13497 | 1668 KiB | 1732 KiB |
| `Eijen-256` | hash_128 | 13497 | 1660 KiB | 1776 KiB |
| `Eijen-256` | hash_512 | 13497 | 1668 KiB | 1772 KiB |
| `Eijen-256` | hash_1024 | 13497 | 1684 KiB | 1748 KiB |
| `Eijen-256` | hash_4096 | 13497 | 1692 KiB | 1756 KiB |
| `Eijen-256` | hash_8192 | 13497 | 1680 KiB | 1784 KiB |
| `Eijen-256` | hash_16384 | 13497 | 1708 KiB | 1788 KiB |
| `Eijen-256` | hash_65536 | 13497 | 1732 KiB | 1840 KiB |
| `Eijen-384` | hash_32 | 13497 | 1684 KiB | 1768 KiB |
| `Eijen-384` | hash_128 | 13497 | 1672 KiB | 1776 KiB |
| `Eijen-384` | hash_512 | 13497 | 1688 KiB | 1752 KiB |
| `Eijen-384` | hash_1024 | 13497 | 1692 KiB | 1780 KiB |
| `Eijen-384` | hash_4096 | 13497 | 1676 KiB | 1740 KiB |
| `Eijen-384` | hash_8192 | 13497 | 1676 KiB | 1776 KiB |
| `Eijen-384` | hash_16384 | 13497 | 1704 KiB | 1768 KiB |
| `Eijen-384` | hash_65536 | 13497 | 1736 KiB | 1844 KiB |
| `Eijen-512` | hash_32 | 13497 | 1684 KiB | 1748 KiB |
| `Eijen-512` | hash_128 | 13497 | 1688 KiB | 1752 KiB |
| `Eijen-512` | hash_512 | 13497 | 1684 KiB | 1776 KiB |
| `Eijen-512` | hash_1024 | 13497 | 1668 KiB | 1768 KiB |
| `Eijen-512` | hash_4096 | 13497 | 1684 KiB | 1784 KiB |
| `Eijen-512` | hash_8192 | 13497 | 1692 KiB | 1756 KiB |
| `Eijen-512` | hash_16384 | 13497 | 1684 KiB | 1784 KiB |
| `Eijen-512` | hash_65536 | 13497 | 1748 KiB | 1840 KiB |
| `Eijen-768` | hash_32 | 13497 | 1680 KiB | 1756 KiB |
| `Eijen-768` | hash_128 | 13497 | 1692 KiB | 1776 KiB |
| `Eijen-768` | hash_512 | 13497 | 1688 KiB | 1772 KiB |
| `Eijen-768` | hash_1024 | 13497 | 1680 KiB | 1744 KiB |
| `Eijen-768` | hash_4096 | 13497 | 1692 KiB | 1772 KiB |
| `Eijen-768` | hash_8192 | 13497 | 1692 KiB | 1776 KiB |
| `Eijen-768` | hash_16384 | 13497 | 1704 KiB | 1796 KiB |
| `Eijen-768` | hash_65536 | 13497 | 1736 KiB | 1824 KiB |
| `Eijen-1024` | hash_32 | 13497 | 1684 KiB | 1760 KiB |
| `Eijen-1024` | hash_128 | 13497 | 1680 KiB | 1744 KiB |
| `Eijen-1024` | hash_512 | 13497 | 1688 KiB | 1768 KiB |
| `Eijen-1024` | hash_1024 | 13497 | 1660 KiB | 1724 KiB |
| `Eijen-1024` | hash_4096 | 13497 | 1676 KiB | 1780 KiB |
| `Eijen-1024` | hash_8192 | 13497 | 1688 KiB | 1752 KiB |
| `Eijen-1024` | hash_16384 | 13497 | 1704 KiB | 1768 KiB |
| `Eijen-1024` | hash_65536 | 13497 | 1756 KiB | 1820 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Eijen-256` | KAT log (sha256 `b701bed89eff869f…`) | `kat/hash-09/Eijen-256.log` |
| `Eijen-256` | timing hash_1024 | `records/hash-09/Eijen-256__hash_1024.json` |
| `Eijen-256` | timing hash_128 | `records/hash-09/Eijen-256__hash_128.json` |
| `Eijen-256` | timing hash_16384 | `records/hash-09/Eijen-256__hash_16384.json` |
| `Eijen-256` | timing hash_32 | `records/hash-09/Eijen-256__hash_32.json` |
| `Eijen-256` | timing hash_4096 | `records/hash-09/Eijen-256__hash_4096.json` |
| `Eijen-256` | timing hash_512 | `records/hash-09/Eijen-256__hash_512.json` |
| `Eijen-256` | timing hash_65536 | `records/hash-09/Eijen-256__hash_65536.json` |
| `Eijen-256` | timing hash_8192 | `records/hash-09/Eijen-256__hash_8192.json` |
| `Eijen-384` | KAT log (sha256 `564af2ca9497f8e8…`) | `kat/hash-09/Eijen-384.log` |
| `Eijen-384` | timing hash_1024 | `records/hash-09/Eijen-384__hash_1024.json` |
| `Eijen-384` | timing hash_128 | `records/hash-09/Eijen-384__hash_128.json` |
| `Eijen-384` | timing hash_16384 | `records/hash-09/Eijen-384__hash_16384.json` |
| `Eijen-384` | timing hash_32 | `records/hash-09/Eijen-384__hash_32.json` |
| `Eijen-384` | timing hash_4096 | `records/hash-09/Eijen-384__hash_4096.json` |
| `Eijen-384` | timing hash_512 | `records/hash-09/Eijen-384__hash_512.json` |
| `Eijen-384` | timing hash_65536 | `records/hash-09/Eijen-384__hash_65536.json` |
| `Eijen-384` | timing hash_8192 | `records/hash-09/Eijen-384__hash_8192.json` |
| `Eijen-512` | KAT log (sha256 `8ad2ce23a76e277b…`) | `kat/hash-09/Eijen-512.log` |
| `Eijen-512` | timing hash_1024 | `records/hash-09/Eijen-512__hash_1024.json` |
| `Eijen-512` | timing hash_128 | `records/hash-09/Eijen-512__hash_128.json` |
| `Eijen-512` | timing hash_16384 | `records/hash-09/Eijen-512__hash_16384.json` |
| `Eijen-512` | timing hash_32 | `records/hash-09/Eijen-512__hash_32.json` |
| `Eijen-512` | timing hash_4096 | `records/hash-09/Eijen-512__hash_4096.json` |
| `Eijen-512` | timing hash_512 | `records/hash-09/Eijen-512__hash_512.json` |
| `Eijen-512` | timing hash_65536 | `records/hash-09/Eijen-512__hash_65536.json` |
| `Eijen-512` | timing hash_8192 | `records/hash-09/Eijen-512__hash_8192.json` |
| `Eijen-768` | KAT log (sha256 `e3742de9d9f29dca…`) | `kat/hash-09/Eijen-768.log` |
| `Eijen-768` | timing hash_1024 | `records/hash-09/Eijen-768__hash_1024.json` |
| `Eijen-768` | timing hash_128 | `records/hash-09/Eijen-768__hash_128.json` |
| `Eijen-768` | timing hash_16384 | `records/hash-09/Eijen-768__hash_16384.json` |
| `Eijen-768` | timing hash_32 | `records/hash-09/Eijen-768__hash_32.json` |
| `Eijen-768` | timing hash_4096 | `records/hash-09/Eijen-768__hash_4096.json` |
| `Eijen-768` | timing hash_512 | `records/hash-09/Eijen-768__hash_512.json` |
| `Eijen-768` | timing hash_65536 | `records/hash-09/Eijen-768__hash_65536.json` |
| `Eijen-768` | timing hash_8192 | `records/hash-09/Eijen-768__hash_8192.json` |
| `Eijen-1024` | KAT log (sha256 `067f1a47fc002d15…`) | `kat/hash-09/Eijen-1024.log` |
| `Eijen-1024` | timing hash_1024 | `records/hash-09/Eijen-1024__hash_1024.json` |
| `Eijen-1024` | timing hash_128 | `records/hash-09/Eijen-1024__hash_128.json` |
| `Eijen-1024` | timing hash_16384 | `records/hash-09/Eijen-1024__hash_16384.json` |
| `Eijen-1024` | timing hash_32 | `records/hash-09/Eijen-1024__hash_32.json` |
| `Eijen-1024` | timing hash_4096 | `records/hash-09/Eijen-1024__hash_4096.json` |
| `Eijen-1024` | timing hash_512 | `records/hash-09/Eijen-1024__hash_512.json` |
| `Eijen-1024` | timing hash_65536 | `records/hash-09/Eijen-1024__hash_65536.json` |
| `Eijen-1024` | timing hash_8192 | `records/hash-09/Eijen-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

