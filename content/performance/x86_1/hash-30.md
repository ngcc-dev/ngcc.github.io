<!-- synchronized from harness: hash-30/perf_x86_1.md -->
# hash-30 The ZC-DM Hash Function — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-30` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101534683994607616.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-30.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: The ZC-DM Hash Function
- Implementation versions measured: reference
- Parameter sets: `ZC-DM-1280-512`, `ZC-DM-1280-768`, `ZC-DM-1280-1024`, `ZC-DM-1536-512`, `ZC-DM-1536-768`, `ZC-DM-1536-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-30/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `ZC-DM-1280-512` | guide | PASS |
| `ZC-DM-1280-768` | guide | PASS |
| `ZC-DM-1280-1024` | guide | PASS |
| `ZC-DM-1536-512` | guide | PASS |
| `ZC-DM-1536-768` | guide | PASS |
| `ZC-DM-1536-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `ZC-DM-1280-512` | 32 B | 1219 | 38.1 | 584 ns | 54.8 | 100000 (5 × 20000) |
| `ZC-DM-1280-512` | 128 B | 1750 | 13.7 | 838 ns | 152.7 | 100000 (5 × 20000) |
| `ZC-DM-1280-512` | 512 B | 3972 | 7.8 | 1.9 µs | 269.6 | 100000 (5 × 20000) |
| `ZC-DM-1280-512` | 1024 B | 7725 | 7.5 | 3.69 µs | 277.3 | 100000 (5 × 20000) |
| `ZC-DM-1280-512` | 4096 B | 28.5 k | 7.0 | 13.6 µs | 300.7 | 100000 (5 × 20000) |
| `ZC-DM-1280-512` | 8192 B | 56.3 k | 6.9 | 26.9 µs | 304.8 | 100000 (5 × 20000) |
| `ZC-DM-1280-512` | 16384 B | 111.2 k | 6.8 | 53.1 µs | 308.3 | 85120 (5 × 17024) |
| `ZC-DM-1280-512` | 65536 B | 442.1 k | 6.7 | 211 µs | 310.3 | 23865 (5 × 4773) |
| `ZC-DM-1280-768` | 32 B | 1570 | 49.0 | 751 ns | 42.6 | 100000 (5 × 20000) |
| `ZC-DM-1280-768` | 128 B | 2931 | 22.9 | 1.4 µs | 91.2 | 100000 (5 × 20000) |
| `ZC-DM-1280-768` | 512 B | 7122 | 13.9 | 3.4 µs | 150.4 | 100000 (5 × 20000) |
| `ZC-DM-1280-768` | 1024 B | 12.4 k | 12.1 | 5.91 µs | 173.4 | 100000 (5 × 20000) |
| `ZC-DM-1280-768` | 4096 B | 44.4 k | 10.9 | 21.2 µs | 192.9 | 100000 (5 × 20000) |
| `ZC-DM-1280-768` | 8192 B | 86.9 k | 10.6 | 41.5 µs | 197.3 | 87455 (5 × 17491) |
| `ZC-DM-1280-768` | 16384 B | 174.0 k | 10.6 | 83.1 µs | 197.1 | 57125 (5 × 11425) |
| `ZC-DM-1280-768` | 65536 B | 691.9 k | 10.6 | 331 µs | 198.3 | 15440 (5 × 3088) |
| `ZC-DM-1280-1024` | 32 B | 4305 | 134.5 | 2.06 µs | 15.5 | 100000 (5 × 20000) |
| `ZC-DM-1280-1024` | 128 B | 6736 | 52.6 | 3.22 µs | 39.8 | 100000 (5 × 20000) |
| `ZC-DM-1280-1024` | 512 B | 16.0 k | 31.2 | 7.63 µs | 67.1 | 100000 (5 × 20000) |
| `ZC-DM-1280-1024` | 1024 B | 28.2 k | 27.5 | 13.5 µs | 76.1 | 100000 (5 × 20000) |
| `ZC-DM-1280-1024` | 4096 B | 102.2 k | 25.0 | 48.8 µs | 83.9 | 90135 (5 × 18027) |
| `ZC-DM-1280-1024` | 8192 B | 202.2 k | 24.7 | 96.6 µs | 84.8 | 48865 (5 × 9773) |
| `ZC-DM-1280-1024` | 16384 B | 399.5 k | 24.4 | 191 µs | 85.9 | 25365 (5 × 5073) |
| `ZC-DM-1280-1024` | 65536 B | 1.59 M | 24.3 | 762 µs | 86.1 | 6660 (5 × 1332) |
| `ZC-DM-1536-512` | 32 B | 1915 | 59.8 | 920 ns | 34.8 | 100000 (5 × 20000) |
| `ZC-DM-1536-512` | 128 B | 3161 | 24.7 | 1.52 µs | 84.4 | 100000 (5 × 20000) |
| `ZC-DM-1536-512` | 512 B | 6186 | 12.1 | 2.96 µs | 172.8 | 100000 (5 × 20000) |
| `ZC-DM-1536-512` | 1024 B | 10.2 k | 9.9 | 4.88 µs | 210.0 | 100000 (5 × 20000) |
| `ZC-DM-1536-512` | 4096 B | 38.2 k | 9.3 | 18.3 µs | 223.7 | 100000 (5 × 20000) |
| `ZC-DM-1536-512` | 8192 B | 74.6 k | 9.1 | 35.7 µs | 229.4 | 100000 (5 × 20000) |
| `ZC-DM-1536-512` | 16384 B | 147.2 k | 9.0 | 70.5 µs | 232.5 | 64760 (5 × 12952) |
| `ZC-DM-1536-512` | 65536 B | 581.9 k | 8.9 | 279 µs | 235.3 | 17450 (5 × 3490) |
| `ZC-DM-1536-768` | 32 B | 2675 | 83.6 | 1.28 µs | 24.9 | 100000 (5 × 20000) |
| `ZC-DM-1536-768` | 128 B | 3655 | 28.6 | 1.75 µs | 73.1 | 100000 (5 × 20000) |
| `ZC-DM-1536-768` | 512 B | 7651 | 14.9 | 3.67 µs | 139.7 | 100000 (5 × 20000) |
| `ZC-DM-1536-768` | 1024 B | 14.2 k | 13.8 | 6.78 µs | 151.1 | 100000 (5 × 20000) |
| `ZC-DM-1536-768` | 4096 B | 51.1 k | 12.5 | 24.4 µs | 167.6 | 100000 (5 × 20000) |
| `ZC-DM-1536-768` | 8192 B | 100.6 k | 12.3 | 48.2 µs | 170.0 | 38140 (5 × 7628) |
| `ZC-DM-1536-768` | 16384 B | 199.7 k | 12.2 | 95.6 µs | 171.3 | 48755 (5 × 9751) |
| `ZC-DM-1536-768` | 65536 B | 786.4 k | 12.0 | 376 µs | 174.1 | 13035 (5 × 2607) |
| `ZC-DM-1536-1024` | 32 B | 3433 | 107.3 | 1.64 µs | 19.5 | 100000 (5 × 20000) |
| `ZC-DM-1536-1024` | 128 B | 5661 | 44.2 | 2.71 µs | 47.3 | 100000 (5 × 20000) |
| `ZC-DM-1536-1024` | 512 B | 13.2 k | 25.7 | 6.31 µs | 81.2 | 100000 (5 × 20000) |
| `ZC-DM-1536-1024` | 1024 B | 22.6 k | 22.1 | 10.8 µs | 94.6 | 100000 (5 × 20000) |
| `ZC-DM-1536-1024` | 4096 B | 80.9 k | 19.8 | 38.7 µs | 105.8 | 100000 (5 × 20000) |
| `ZC-DM-1536-1024` | 8192 B | 157.8 k | 19.3 | 75.5 µs | 108.5 | 60755 (5 × 12151) |
| `ZC-DM-1536-1024` | 16384 B | 312.0 k | 19.0 | 149 µs | 109.7 | 30140 (5 × 6028) |
| `ZC-DM-1536-1024` | 65536 B | 1.24 M | 18.9 | 592 µs | 110.8 | 8425 (5 × 1685) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `ZC-DM-1280-512` | hash_32 | 15461 | 1668 KiB | 1776 KiB |
| `ZC-DM-1280-512` | hash_128 | 15461 | 1656 KiB | 1780 KiB |
| `ZC-DM-1280-512` | hash_512 | 15461 | 1676 KiB | 1740 KiB |
| `ZC-DM-1280-512` | hash_1024 | 15461 | 1668 KiB | 1784 KiB |
| `ZC-DM-1280-512` | hash_4096 | 15461 | 1700 KiB | 1788 KiB |
| `ZC-DM-1280-512` | hash_8192 | 15461 | 1680 KiB | 1780 KiB |
| `ZC-DM-1280-512` | hash_16384 | 15461 | 1708 KiB | 1788 KiB |
| `ZC-DM-1280-512` | hash_65536 | 15461 | 1748 KiB | 1812 KiB |
| `ZC-DM-1280-768` | hash_32 | 15461 | 1692 KiB | 1756 KiB |
| `ZC-DM-1280-768` | hash_128 | 15461 | 1676 KiB | 1780 KiB |
| `ZC-DM-1280-768` | hash_512 | 15461 | 1676 KiB | 1776 KiB |
| `ZC-DM-1280-768` | hash_1024 | 15461 | 1672 KiB | 1736 KiB |
| `ZC-DM-1280-768` | hash_4096 | 15461 | 1688 KiB | 1752 KiB |
| `ZC-DM-1280-768` | hash_8192 | 15461 | 1688 KiB | 1788 KiB |
| `ZC-DM-1280-768` | hash_16384 | 15461 | 1684 KiB | 1800 KiB |
| `ZC-DM-1280-768` | hash_65536 | 15461 | 1740 KiB | 1844 KiB |
| `ZC-DM-1280-1024` | hash_32 | 15461 | 1680 KiB | 1776 KiB |
| `ZC-DM-1280-1024` | hash_128 | 15461 | 1676 KiB | 1776 KiB |
| `ZC-DM-1280-1024` | hash_512 | 15461 | 1692 KiB | 1776 KiB |
| `ZC-DM-1280-1024` | hash_1024 | 15461 | 1644 KiB | 1772 KiB |
| `ZC-DM-1280-1024` | hash_4096 | 15461 | 1696 KiB | 1768 KiB |
| `ZC-DM-1280-1024` | hash_8192 | 15461 | 1652 KiB | 1780 KiB |
| `ZC-DM-1280-1024` | hash_16384 | 15461 | 1684 KiB | 1748 KiB |
| `ZC-DM-1280-1024` | hash_65536 | 15461 | 1756 KiB | 1836 KiB |
| `ZC-DM-1536-512` | hash_32 | 24029 | 1676 KiB | 1792 KiB |
| `ZC-DM-1536-512` | hash_128 | 24029 | 1676 KiB | 1740 KiB |
| `ZC-DM-1536-512` | hash_512 | 24029 | 1700 KiB | 1764 KiB |
| `ZC-DM-1536-512` | hash_1024 | 24029 | 1672 KiB | 1792 KiB |
| `ZC-DM-1536-512` | hash_4096 | 24029 | 1704 KiB | 1784 KiB |
| `ZC-DM-1536-512` | hash_8192 | 24029 | 1684 KiB | 1748 KiB |
| `ZC-DM-1536-512` | hash_16384 | 24029 | 1708 KiB | 1808 KiB |
| `ZC-DM-1536-512` | hash_65536 | 24029 | 1756 KiB | 1832 KiB |
| `ZC-DM-1536-768` | hash_32 | 24029 | 1700 KiB | 1792 KiB |
| `ZC-DM-1536-768` | hash_128 | 24029 | 1652 KiB | 1780 KiB |
| `ZC-DM-1536-768` | hash_512 | 24029 | 1680 KiB | 1768 KiB |
| `ZC-DM-1536-768` | hash_1024 | 24029 | 1692 KiB | 1756 KiB |
| `ZC-DM-1536-768` | hash_4096 | 24029 | 1688 KiB | 1796 KiB |
| `ZC-DM-1536-768` | hash_8192 | 24029 | 1708 KiB | 1780 KiB |
| `ZC-DM-1536-768` | hash_16384 | 24029 | 1704 KiB | 1808 KiB |
| `ZC-DM-1536-768` | hash_65536 | 24029 | 1720 KiB | 1848 KiB |
| `ZC-DM-1536-1024` | hash_32 | 24029 | 1692 KiB | 1756 KiB |
| `ZC-DM-1536-1024` | hash_128 | 24029 | 1676 KiB | 1740 KiB |
| `ZC-DM-1536-1024` | hash_512 | 24029 | 1700 KiB | 1792 KiB |
| `ZC-DM-1536-1024` | hash_1024 | 24029 | 1684 KiB | 1788 KiB |
| `ZC-DM-1536-1024` | hash_4096 | 24029 | 1684 KiB | 1796 KiB |
| `ZC-DM-1536-1024` | hash_8192 | 24029 | 1688 KiB | 1796 KiB |
| `ZC-DM-1536-1024` | hash_16384 | 24029 | 1708 KiB | 1772 KiB |
| `ZC-DM-1536-1024` | hash_65536 | 24029 | 1736 KiB | 1800 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `ZC-DM-1280-512` | KAT log (sha256 `808bf1bd2fd70101…`) | `kat/hash-30/ZC-DM-1280-512.log` |
| `ZC-DM-1280-512` | timing hash_1024 | `records/hash-30/ZC-DM-1280-512__hash_1024.json` |
| `ZC-DM-1280-512` | timing hash_128 | `records/hash-30/ZC-DM-1280-512__hash_128.json` |
| `ZC-DM-1280-512` | timing hash_16384 | `records/hash-30/ZC-DM-1280-512__hash_16384.json` |
| `ZC-DM-1280-512` | timing hash_32 | `records/hash-30/ZC-DM-1280-512__hash_32.json` |
| `ZC-DM-1280-512` | timing hash_4096 | `records/hash-30/ZC-DM-1280-512__hash_4096.json` |
| `ZC-DM-1280-512` | timing hash_512 | `records/hash-30/ZC-DM-1280-512__hash_512.json` |
| `ZC-DM-1280-512` | timing hash_65536 | `records/hash-30/ZC-DM-1280-512__hash_65536.json` |
| `ZC-DM-1280-512` | timing hash_8192 | `records/hash-30/ZC-DM-1280-512__hash_8192.json` |
| `ZC-DM-1280-768` | KAT log (sha256 `e98e0b737c72d4ae…`) | `kat/hash-30/ZC-DM-1280-768.log` |
| `ZC-DM-1280-768` | timing hash_1024 | `records/hash-30/ZC-DM-1280-768__hash_1024.json` |
| `ZC-DM-1280-768` | timing hash_128 | `records/hash-30/ZC-DM-1280-768__hash_128.json` |
| `ZC-DM-1280-768` | timing hash_16384 | `records/hash-30/ZC-DM-1280-768__hash_16384.json` |
| `ZC-DM-1280-768` | timing hash_32 | `records/hash-30/ZC-DM-1280-768__hash_32.json` |
| `ZC-DM-1280-768` | timing hash_4096 | `records/hash-30/ZC-DM-1280-768__hash_4096.json` |
| `ZC-DM-1280-768` | timing hash_512 | `records/hash-30/ZC-DM-1280-768__hash_512.json` |
| `ZC-DM-1280-768` | timing hash_65536 | `records/hash-30/ZC-DM-1280-768__hash_65536.json` |
| `ZC-DM-1280-768` | timing hash_8192 | `records/hash-30/ZC-DM-1280-768__hash_8192.json` |
| `ZC-DM-1280-1024` | KAT log (sha256 `e8e4a83288708518…`) | `kat/hash-30/ZC-DM-1280-1024.log` |
| `ZC-DM-1280-1024` | timing hash_1024 | `records/hash-30/ZC-DM-1280-1024__hash_1024.json` |
| `ZC-DM-1280-1024` | timing hash_128 | `records/hash-30/ZC-DM-1280-1024__hash_128.json` |
| `ZC-DM-1280-1024` | timing hash_16384 | `records/hash-30/ZC-DM-1280-1024__hash_16384.json` |
| `ZC-DM-1280-1024` | timing hash_32 | `records/hash-30/ZC-DM-1280-1024__hash_32.json` |
| `ZC-DM-1280-1024` | timing hash_4096 | `records/hash-30/ZC-DM-1280-1024__hash_4096.json` |
| `ZC-DM-1280-1024` | timing hash_512 | `records/hash-30/ZC-DM-1280-1024__hash_512.json` |
| `ZC-DM-1280-1024` | timing hash_65536 | `records/hash-30/ZC-DM-1280-1024__hash_65536.json` |
| `ZC-DM-1280-1024` | timing hash_8192 | `records/hash-30/ZC-DM-1280-1024__hash_8192.json` |
| `ZC-DM-1536-512` | KAT log (sha256 `72f7c3873c62a725…`) | `kat/hash-30/ZC-DM-1536-512.log` |
| `ZC-DM-1536-512` | timing hash_1024 | `records/hash-30/ZC-DM-1536-512__hash_1024.json` |
| `ZC-DM-1536-512` | timing hash_128 | `records/hash-30/ZC-DM-1536-512__hash_128.json` |
| `ZC-DM-1536-512` | timing hash_16384 | `records/hash-30/ZC-DM-1536-512__hash_16384.json` |
| `ZC-DM-1536-512` | timing hash_32 | `records/hash-30/ZC-DM-1536-512__hash_32.json` |
| `ZC-DM-1536-512` | timing hash_4096 | `records/hash-30/ZC-DM-1536-512__hash_4096.json` |
| `ZC-DM-1536-512` | timing hash_512 | `records/hash-30/ZC-DM-1536-512__hash_512.json` |
| `ZC-DM-1536-512` | timing hash_65536 | `records/hash-30/ZC-DM-1536-512__hash_65536.json` |
| `ZC-DM-1536-512` | timing hash_8192 | `records/hash-30/ZC-DM-1536-512__hash_8192.json` |
| `ZC-DM-1536-768` | KAT log (sha256 `506f6e02c1454f56…`) | `kat/hash-30/ZC-DM-1536-768.log` |
| `ZC-DM-1536-768` | timing hash_1024 | `records/hash-30/ZC-DM-1536-768__hash_1024.json` |
| `ZC-DM-1536-768` | timing hash_128 | `records/hash-30/ZC-DM-1536-768__hash_128.json` |
| `ZC-DM-1536-768` | timing hash_16384 | `records/hash-30/ZC-DM-1536-768__hash_16384.json` |
| `ZC-DM-1536-768` | timing hash_32 | `records/hash-30/ZC-DM-1536-768__hash_32.json` |
| `ZC-DM-1536-768` | timing hash_4096 | `records/hash-30/ZC-DM-1536-768__hash_4096.json` |
| `ZC-DM-1536-768` | timing hash_512 | `records/hash-30/ZC-DM-1536-768__hash_512.json` |
| `ZC-DM-1536-768` | timing hash_65536 | `records/hash-30/ZC-DM-1536-768__hash_65536.json` |
| `ZC-DM-1536-768` | timing hash_8192 | `records/hash-30/ZC-DM-1536-768__hash_8192.json` |
| `ZC-DM-1536-1024` | KAT log (sha256 `d69ac5a3757868eb…`) | `kat/hash-30/ZC-DM-1536-1024.log` |
| `ZC-DM-1536-1024` | timing hash_1024 | `records/hash-30/ZC-DM-1536-1024__hash_1024.json` |
| `ZC-DM-1536-1024` | timing hash_128 | `records/hash-30/ZC-DM-1536-1024__hash_128.json` |
| `ZC-DM-1536-1024` | timing hash_16384 | `records/hash-30/ZC-DM-1536-1024__hash_16384.json` |
| `ZC-DM-1536-1024` | timing hash_32 | `records/hash-30/ZC-DM-1536-1024__hash_32.json` |
| `ZC-DM-1536-1024` | timing hash_4096 | `records/hash-30/ZC-DM-1536-1024__hash_4096.json` |
| `ZC-DM-1536-1024` | timing hash_512 | `records/hash-30/ZC-DM-1536-1024__hash_512.json` |
| `ZC-DM-1536-1024` | timing hash_65536 | `records/hash-30/ZC-DM-1536-1024__hash_65536.json` |
| `ZC-DM-1536-1024` | timing hash_8192 | `records/hash-30/ZC-DM-1536-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

