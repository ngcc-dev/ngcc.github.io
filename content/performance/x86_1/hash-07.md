<!-- synchronized from harness: hash-07/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-07</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101539781751689216.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-07.md">arm_1</a></p>

# hash-07 Dragon Hash Family — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Dragon Hash Family
- Implementation versions measured: reference
- Parameter sets: `Dragon-512`, `Dragon-768`, `Dragon-1024`, `Dragon-XOF-256`, `Dragon-XOF-384`, `Dragon-XOF-512`
- Security evaluation: [hash-07 report](../../reports/hash-07.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-07/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Dragon-512` | guide | PASS |
| `Dragon-768` | guide | PASS |
| `Dragon-1024` | guide | PASS |
| `Dragon-XOF-256` | guide | PASS |
| `Dragon-XOF-384` | guide | PASS |
| `Dragon-XOF-512` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Dragon-512` | 32 B | 2436 | 76.1 | 1.17 µs | 27.4 | 100000 (5 × 20000) |
| `Dragon-512` | 128 B | 4791 | 37.4 | 2.3 µs | 55.7 | 100000 (5 × 20000) |
| `Dragon-512` | 512 B | 11.6 k | 22.6 | 5.55 µs | 92.2 | 100000 (5 × 20000) |
| `Dragon-512` | 1024 B | 20.4 k | 19.9 | 9.77 µs | 104.8 | 100000 (5 × 20000) |
| `Dragon-512` | 4096 B | 75.3 k | 18.4 | 36 µs | 113.7 | 100000 (5 × 20000) |
| `Dragon-512` | 8192 B | 149.0 k | 18.2 | 71.3 µs | 115.0 | 66700 (5 × 13340) |
| `Dragon-512` | 16384 B | 293.2 k | 17.9 | 140 µs | 116.8 | 33715 (5 × 6743) |
| `Dragon-512` | 65536 B | 1.17 M | 17.8 | 559 µs | 117.3 | 8940 (5 × 1788) |
| `Dragon-768` | 32 B | 2418 | 75.6 | 1.16 µs | 27.6 | 100000 (5 × 20000) |
| `Dragon-768` | 128 B | 4786 | 37.4 | 2.29 µs | 55.8 | 100000 (5 × 20000) |
| `Dragon-768` | 512 B | 14.0 k | 27.3 | 6.68 µs | 76.6 | 100000 (5 × 20000) |
| `Dragon-768` | 1024 B | 25.4 k | 24.8 | 12.2 µs | 84.2 | 100000 (5 × 20000) |
| `Dragon-768` | 4096 B | 99.3 k | 24.2 | 47.5 µs | 86.2 | 87440 (5 × 17488) |
| `Dragon-768` | 8192 B | 196.9 k | 24.0 | 94.3 µs | 86.9 | 50085 (5 × 10017) |
| `Dragon-768` | 16384 B | 389.0 k | 23.7 | 186 µs | 88.0 | 25750 (5 × 5150) |
| `Dragon-768` | 65536 B | 1.57 M | 24.0 | 753 µs | 87.1 | 6520 (5 × 1304) |
| `Dragon-1024` | 32 B | 2424 | 75.8 | 1.16 µs | 27.5 | 100000 (5 × 20000) |
| `Dragon-1024` | 128 B | 7257 | 56.7 | 3.47 µs | 36.8 | 100000 (5 × 20000) |
| `Dragon-1024` | 512 B | 21.0 k | 41.0 | 10.1 µs | 50.9 | 100000 (5 × 20000) |
| `Dragon-1024` | 1024 B | 39.6 k | 38.7 | 19 µs | 54.0 | 100000 (5 × 20000) |
| `Dragon-1024` | 4096 B | 151.0 k | 36.9 | 72.2 µs | 56.7 | 65180 (5 × 13036) |
| `Dragon-1024` | 8192 B | 299.1 k | 36.5 | 143 µs | 57.2 | 34340 (5 × 6868) |
| `Dragon-1024` | 16384 B | 588.0 k | 35.9 | 281 µs | 58.2 | 17340 (5 × 3468) |
| `Dragon-1024` | 65536 B | 2.37 M | 36.2 | 1.14 ms | 57.7 | 4415 (5 × 883) |
| `Dragon-XOF-256` | 32 B | 9860 | 308.1 | 4.72 µs | 6.8 | 100000 (5 × 20000) |
| `Dragon-XOF-256` | 128 B | 12.2 k | 95.0 | 5.82 µs | 22.0 | 100000 (5 × 20000) |
| `Dragon-XOF-256` | 512 B | 19.2 k | 37.5 | 9.19 µs | 55.7 | 100000 (5 × 20000) |
| `Dragon-XOF-256` | 1024 B | 28.1 k | 27.5 | 13.5 µs | 76.1 | 100000 (5 × 20000) |
| `Dragon-XOF-256` | 4096 B | 82.1 k | 20.1 | 39.3 µs | 104.2 | 100000 (5 × 20000) |
| `Dragon-XOF-256` | 8192 B | 154.3 k | 18.8 | 73.8 µs | 110.9 | 62880 (5 × 12576) |
| `Dragon-XOF-256` | 16384 B | 297.0 k | 18.1 | 142 µs | 115.3 | 34240 (5 × 6848) |
| `Dragon-XOF-256` | 65536 B | 1.20 M | 18.3 | 573 µs | 114.4 | 9035 (5 × 1807) |
| `Dragon-XOF-384` | 32 B | 9114 | 284.8 | 4.36 µs | 7.3 | 100000 (5 × 20000) |
| `Dragon-XOF-384` | 128 B | 11.4 k | 89.4 | 5.47 µs | 23.4 | 100000 (5 × 20000) |
| `Dragon-XOF-384` | 512 B | 20.8 k | 40.5 | 9.94 µs | 51.5 | 100000 (5 × 20000) |
| `Dragon-XOF-384` | 1024 B | 32.1 k | 31.4 | 15.4 µs | 66.6 | 100000 (5 × 20000) |
| `Dragon-XOF-384` | 4096 B | 106.7 k | 26.1 | 51.1 µs | 80.2 | 82885 (5 × 16577) |
| `Dragon-XOF-384` | 8192 B | 203.2 k | 24.8 | 97.2 µs | 84.2 | 49045 (5 × 9809) |
| `Dragon-XOF-384` | 16384 B | 400.2 k | 24.4 | 192 µs | 85.5 | 25670 (5 × 5134) |
| `Dragon-XOF-384` | 65536 B | 1.57 M | 24.0 | 751 µs | 87.2 | 6665 (5 × 1333) |
| `Dragon-XOF-512` | 32 B | 8367 | 261.5 | 4 µs | 8.0 | 100000 (5 × 20000) |
| `Dragon-XOF-512` | 128 B | 13.1 k | 102.5 | 6.28 µs | 20.4 | 100000 (5 × 20000) |
| `Dragon-XOF-512` | 512 B | 27.0 k | 52.8 | 12.9 µs | 39.6 | 100000 (5 × 20000) |
| `Dragon-XOF-512` | 1024 B | 45.4 k | 44.4 | 21.7 µs | 47.1 | 100000 (5 × 20000) |
| `Dragon-XOF-512` | 4096 B | 156.5 k | 38.2 | 74.9 µs | 54.7 | 58840 (5 × 11768) |
| `Dragon-XOF-512` | 8192 B | 307.4 k | 37.5 | 147 µs | 55.7 | 32815 (5 × 6563) |
| `Dragon-XOF-512` | 16384 B | 601.5 k | 36.7 | 288 µs | 56.9 | 17475 (5 × 3495) |
| `Dragon-XOF-512` | 65536 B | 2.38 M | 36.4 | 1.14 ms | 57.5 | 4405 (5 × 881) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Dragon-512` | hash_32 | 12921 | 1672 KiB | 1760 KiB |
| `Dragon-512` | hash_128 | 12921 | 1672 KiB | 1736 KiB |
| `Dragon-512` | hash_512 | 12921 | 1692 KiB | 1756 KiB |
| `Dragon-512` | hash_1024 | 12921 | 1676 KiB | 1740 KiB |
| `Dragon-512` | hash_4096 | 12921 | 1668 KiB | 1776 KiB |
| `Dragon-512` | hash_8192 | 12921 | 1684 KiB | 1764 KiB |
| `Dragon-512` | hash_16384 | 12921 | 1688 KiB | 1788 KiB |
| `Dragon-512` | hash_65536 | 12921 | 1736 KiB | 1840 KiB |
| `Dragon-768` | hash_32 | 12953 | 1664 KiB | 1728 KiB |
| `Dragon-768` | hash_128 | 12953 | 1676 KiB | 1740 KiB |
| `Dragon-768` | hash_512 | 12953 | 1668 KiB | 1732 KiB |
| `Dragon-768` | hash_1024 | 12953 | 1676 KiB | 1776 KiB |
| `Dragon-768` | hash_4096 | 12953 | 1668 KiB | 1772 KiB |
| `Dragon-768` | hash_8192 | 12953 | 1696 KiB | 1784 KiB |
| `Dragon-768` | hash_16384 | 12953 | 1696 KiB | 1760 KiB |
| `Dragon-768` | hash_65536 | 12953 | 1704 KiB | 1832 KiB |
| `Dragon-1024` | hash_32 | 12865 | 1688 KiB | 1764 KiB |
| `Dragon-1024` | hash_128 | 12865 | 1680 KiB | 1760 KiB |
| `Dragon-1024` | hash_512 | 12865 | 1688 KiB | 1760 KiB |
| `Dragon-1024` | hash_1024 | 12865 | 1684 KiB | 1768 KiB |
| `Dragon-1024` | hash_4096 | 12865 | 1684 KiB | 1784 KiB |
| `Dragon-1024` | hash_8192 | 12865 | 1680 KiB | 1788 KiB |
| `Dragon-1024` | hash_16384 | 12865 | 1612 KiB | 1740 KiB |
| `Dragon-1024` | hash_65536 | 12865 | 1732 KiB | 1832 KiB |
| `Dragon-XOF-256` | hash_32 | 13409 | 1664 KiB | 1760 KiB |
| `Dragon-XOF-256` | hash_128 | 13409 | 1664 KiB | 1768 KiB |
| `Dragon-XOF-256` | hash_512 | 13409 | 1668 KiB | 1732 KiB |
| `Dragon-XOF-256` | hash_1024 | 13409 | 1668 KiB | 1756 KiB |
| `Dragon-XOF-256` | hash_4096 | 13409 | 1692 KiB | 1772 KiB |
| `Dragon-XOF-256` | hash_8192 | 13409 | 1680 KiB | 1744 KiB |
| `Dragon-XOF-256` | hash_16384 | 13409 | 1704 KiB | 1792 KiB |
| `Dragon-XOF-256` | hash_65536 | 13409 | 1752 KiB | 1816 KiB |
| `Dragon-XOF-384` | hash_32 | 13473 | 1672 KiB | 1736 KiB |
| `Dragon-XOF-384` | hash_128 | 13473 | 1692 KiB | 1756 KiB |
| `Dragon-XOF-384` | hash_512 | 13473 | 1664 KiB | 1728 KiB |
| `Dragon-XOF-384` | hash_1024 | 13473 | 1636 KiB | 1764 KiB |
| `Dragon-XOF-384` | hash_4096 | 13473 | 1700 KiB | 1764 KiB |
| `Dragon-XOF-384` | hash_8192 | 13473 | 1704 KiB | 1768 KiB |
| `Dragon-XOF-384` | hash_16384 | 13473 | 1684 KiB | 1800 KiB |
| `Dragon-XOF-384` | hash_65536 | 13473 | 1760 KiB | 1848 KiB |
| `Dragon-XOF-512` | hash_32 | 13361 | 1692 KiB | 1776 KiB |
| `Dragon-XOF-512` | hash_128 | 13361 | 1660 KiB | 1724 KiB |
| `Dragon-XOF-512` | hash_512 | 13361 | 1676 KiB | 1756 KiB |
| `Dragon-XOF-512` | hash_1024 | 13361 | 1668 KiB | 1776 KiB |
| `Dragon-XOF-512` | hash_4096 | 13361 | 1668 KiB | 1772 KiB |
| `Dragon-XOF-512` | hash_8192 | 13361 | 1692 KiB | 1780 KiB |
| `Dragon-XOF-512` | hash_16384 | 13361 | 1688 KiB | 1752 KiB |
| `Dragon-XOF-512` | hash_65536 | 13361 | 1744 KiB | 1840 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Dragon-512` | KAT log (sha256 `ee7e53e5b6444ac8…`) | `kat/hash-07/Dragon-512.log` |
| `Dragon-512` | timing hash_1024 | `records/hash-07/Dragon-512__hash_1024.json` |
| `Dragon-512` | timing hash_128 | `records/hash-07/Dragon-512__hash_128.json` |
| `Dragon-512` | timing hash_16384 | `records/hash-07/Dragon-512__hash_16384.json` |
| `Dragon-512` | timing hash_32 | `records/hash-07/Dragon-512__hash_32.json` |
| `Dragon-512` | timing hash_4096 | `records/hash-07/Dragon-512__hash_4096.json` |
| `Dragon-512` | timing hash_512 | `records/hash-07/Dragon-512__hash_512.json` |
| `Dragon-512` | timing hash_65536 | `records/hash-07/Dragon-512__hash_65536.json` |
| `Dragon-512` | timing hash_8192 | `records/hash-07/Dragon-512__hash_8192.json` |
| `Dragon-768` | KAT log (sha256 `3fcaae89e8474427…`) | `kat/hash-07/Dragon-768.log` |
| `Dragon-768` | timing hash_1024 | `records/hash-07/Dragon-768__hash_1024.json` |
| `Dragon-768` | timing hash_128 | `records/hash-07/Dragon-768__hash_128.json` |
| `Dragon-768` | timing hash_16384 | `records/hash-07/Dragon-768__hash_16384.json` |
| `Dragon-768` | timing hash_32 | `records/hash-07/Dragon-768__hash_32.json` |
| `Dragon-768` | timing hash_4096 | `records/hash-07/Dragon-768__hash_4096.json` |
| `Dragon-768` | timing hash_512 | `records/hash-07/Dragon-768__hash_512.json` |
| `Dragon-768` | timing hash_65536 | `records/hash-07/Dragon-768__hash_65536.json` |
| `Dragon-768` | timing hash_8192 | `records/hash-07/Dragon-768__hash_8192.json` |
| `Dragon-1024` | KAT log (sha256 `525de49a7c05e735…`) | `kat/hash-07/Dragon-1024.log` |
| `Dragon-1024` | timing hash_1024 | `records/hash-07/Dragon-1024__hash_1024.json` |
| `Dragon-1024` | timing hash_128 | `records/hash-07/Dragon-1024__hash_128.json` |
| `Dragon-1024` | timing hash_16384 | `records/hash-07/Dragon-1024__hash_16384.json` |
| `Dragon-1024` | timing hash_32 | `records/hash-07/Dragon-1024__hash_32.json` |
| `Dragon-1024` | timing hash_4096 | `records/hash-07/Dragon-1024__hash_4096.json` |
| `Dragon-1024` | timing hash_512 | `records/hash-07/Dragon-1024__hash_512.json` |
| `Dragon-1024` | timing hash_65536 | `records/hash-07/Dragon-1024__hash_65536.json` |
| `Dragon-1024` | timing hash_8192 | `records/hash-07/Dragon-1024__hash_8192.json` |
| `Dragon-XOF-256` | KAT log (sha256 `e732e6ecbef06712…`) | `kat/hash-07/Dragon-XOF-256.log` |
| `Dragon-XOF-256` | timing hash_1024 | `records/hash-07/Dragon-XOF-256__hash_1024.json` |
| `Dragon-XOF-256` | timing hash_128 | `records/hash-07/Dragon-XOF-256__hash_128.json` |
| `Dragon-XOF-256` | timing hash_16384 | `records/hash-07/Dragon-XOF-256__hash_16384.json` |
| `Dragon-XOF-256` | timing hash_32 | `records/hash-07/Dragon-XOF-256__hash_32.json` |
| `Dragon-XOF-256` | timing hash_4096 | `records/hash-07/Dragon-XOF-256__hash_4096.json` |
| `Dragon-XOF-256` | timing hash_512 | `records/hash-07/Dragon-XOF-256__hash_512.json` |
| `Dragon-XOF-256` | timing hash_65536 | `records/hash-07/Dragon-XOF-256__hash_65536.json` |
| `Dragon-XOF-256` | timing hash_8192 | `records/hash-07/Dragon-XOF-256__hash_8192.json` |
| `Dragon-XOF-384` | KAT log (sha256 `3134cee8b5b589f7…`) | `kat/hash-07/Dragon-XOF-384.log` |
| `Dragon-XOF-384` | timing hash_1024 | `records/hash-07/Dragon-XOF-384__hash_1024.json` |
| `Dragon-XOF-384` | timing hash_128 | `records/hash-07/Dragon-XOF-384__hash_128.json` |
| `Dragon-XOF-384` | timing hash_16384 | `records/hash-07/Dragon-XOF-384__hash_16384.json` |
| `Dragon-XOF-384` | timing hash_32 | `records/hash-07/Dragon-XOF-384__hash_32.json` |
| `Dragon-XOF-384` | timing hash_4096 | `records/hash-07/Dragon-XOF-384__hash_4096.json` |
| `Dragon-XOF-384` | timing hash_512 | `records/hash-07/Dragon-XOF-384__hash_512.json` |
| `Dragon-XOF-384` | timing hash_65536 | `records/hash-07/Dragon-XOF-384__hash_65536.json` |
| `Dragon-XOF-384` | timing hash_8192 | `records/hash-07/Dragon-XOF-384__hash_8192.json` |
| `Dragon-XOF-512` | KAT log (sha256 `9169a0d7cf4da58b…`) | `kat/hash-07/Dragon-XOF-512.log` |
| `Dragon-XOF-512` | timing hash_1024 | `records/hash-07/Dragon-XOF-512__hash_1024.json` |
| `Dragon-XOF-512` | timing hash_128 | `records/hash-07/Dragon-XOF-512__hash_128.json` |
| `Dragon-XOF-512` | timing hash_16384 | `records/hash-07/Dragon-XOF-512__hash_16384.json` |
| `Dragon-XOF-512` | timing hash_32 | `records/hash-07/Dragon-XOF-512__hash_32.json` |
| `Dragon-XOF-512` | timing hash_4096 | `records/hash-07/Dragon-XOF-512__hash_4096.json` |
| `Dragon-XOF-512` | timing hash_512 | `records/hash-07/Dragon-XOF-512__hash_512.json` |
| `Dragon-XOF-512` | timing hash_65536 | `records/hash-07/Dragon-XOF-512__hash_65536.json` |
| `Dragon-XOF-512` | timing hash_8192 | `records/hash-07/Dragon-XOF-512__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

