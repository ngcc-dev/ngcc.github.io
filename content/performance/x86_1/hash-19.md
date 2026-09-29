<!-- synchronized from harness: hash-19/perf_x86_1.md -->
# hash-19 MoFang Hash Function — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-19` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101537228439769088.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-19.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: MoFang Hash Function
- Implementation versions measured: reference
- Parameter sets: `MoFang-256`, `MoFang-256-XOF`, `MoFang-512`, `MoFang-768`, `MoFang-768-XOF`, `MoFang-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-19/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `MoFang-256` | guide | PASS |
| `MoFang-256-XOF` | guide | PASS |
| `MoFang-512` | guide | PASS |
| `MoFang-768` | guide | PASS |
| `MoFang-768-XOF` | guide | PASS |
| `MoFang-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `MoFang-256` | 32 B | 2439 | 76.2 | 1.17 µs | 27.4 | 100000 (5 × 20000) |
| `MoFang-256` | 128 B | 2434 | 19.0 | 1.16 µs | 109.9 | 100000 (5 × 20000) |
| `MoFang-256` | 512 B | 9421 | 18.4 | 4.5 µs | 113.7 | 100000 (5 × 20000) |
| `MoFang-256` | 1024 B | 18.6 k | 18.2 | 8.91 µs | 115.0 | 100000 (5 × 20000) |
| `MoFang-256` | 4096 B | 66.9 k | 16.3 | 32 µs | 128.2 | 100000 (5 × 20000) |
| `MoFang-256` | 8192 B | 131.6 k | 16.1 | 62.9 µs | 130.3 | 67270 (5 × 13454) |
| `MoFang-256` | 16384 B | 262.3 k | 16.0 | 125 µs | 130.8 | 35515 (5 × 7103) |
| `MoFang-256` | 65536 B | 1.05 M | 16.1 | 502 µs | 130.4 | 9165 (5 × 1833) |
| `MoFang-256-XOF` | 32 B | 2504 | 78.3 | 1.2 µs | 26.7 | 100000 (5 × 20000) |
| `MoFang-256-XOF` | 128 B | 2502 | 19.5 | 1.2 µs | 106.9 | 100000 (5 × 20000) |
| `MoFang-256-XOF` | 512 B | 9082 | 17.7 | 4.34 µs | 117.9 | 100000 (5 × 20000) |
| `MoFang-256-XOF` | 1024 B | 17.9 k | 17.5 | 8.55 µs | 119.7 | 100000 (5 × 20000) |
| `MoFang-256-XOF` | 4096 B | 63.8 k | 15.6 | 30.5 µs | 134.3 | 100000 (5 × 20000) |
| `MoFang-256-XOF` | 8192 B | 125.1 k | 15.3 | 59.8 µs | 137.0 | 69465 (5 × 13893) |
| `MoFang-256-XOF` | 16384 B | 249.7 k | 15.2 | 119 µs | 137.3 | 36760 (5 × 7352) |
| `MoFang-256-XOF` | 65536 B | 1.01 M | 15.3 | 481 µs | 136.2 | 9605 (5 × 1921) |
| `MoFang-512` | 32 B | 2554 | 79.8 | 1.22 µs | 26.2 | 100000 (5 × 20000) |
| `MoFang-512` | 128 B | 2512 | 19.6 | 1.2 µs | 106.5 | 100000 (5 × 20000) |
| `MoFang-512` | 512 B | 9512 | 18.6 | 4.55 µs | 112.6 | 100000 (5 × 20000) |
| `MoFang-512` | 1024 B | 18.8 k | 18.3 | 8.96 µs | 114.2 | 100000 (5 × 20000) |
| `MoFang-512` | 4096 B | 67.2 k | 16.4 | 32.1 µs | 127.7 | 100000 (5 × 20000) |
| `MoFang-512` | 8192 B | 131.7 k | 16.1 | 62.9 µs | 130.2 | 68195 (5 × 13639) |
| `MoFang-512` | 16384 B | 262.3 k | 16.0 | 125 µs | 130.8 | 35055 (5 × 7011) |
| `MoFang-512` | 65536 B | 1.05 M | 16.1 | 504 µs | 130.1 | 9255 (5 × 1851) |
| `MoFang-768` | 32 B | 4309 | 134.7 | 2.06 µs | 15.5 | 100000 (5 × 20000) |
| `MoFang-768` | 128 B | 4297 | 33.6 | 2.05 µs | 62.3 | 100000 (5 × 20000) |
| `MoFang-768` | 512 B | 16.6 k | 32.4 | 7.93 µs | 64.6 | 100000 (5 × 20000) |
| `MoFang-768` | 1024 B | 32.7 k | 32.0 | 15.6 µs | 65.5 | 100000 (5 × 20000) |
| `MoFang-768` | 4096 B | 118.0 k | 28.8 | 56.4 µs | 72.6 | 77165 (5 × 15433) |
| `MoFang-768` | 8192 B | 232.0 k | 28.3 | 111 µs | 73.9 | 40880 (5 × 8176) |
| `MoFang-768` | 16384 B | 464.9 k | 28.4 | 222 µs | 73.8 | 21375 (5 × 4275) |
| `MoFang-768` | 65536 B | 1.86 M | 28.4 | 890 µs | 73.7 | 5405 (5 × 1081) |
| `MoFang-768-XOF` | 32 B | 4728 | 147.7 | 2.26 µs | 14.1 | 100000 (5 × 20000) |
| `MoFang-768-XOF` | 128 B | 4705 | 36.8 | 2.25 µs | 56.9 | 100000 (5 × 20000) |
| `MoFang-768-XOF` | 512 B | 16.9 k | 33.1 | 8.09 µs | 63.3 | 100000 (5 × 20000) |
| `MoFang-768-XOF` | 1024 B | 33.1 k | 32.3 | 15.8 µs | 64.8 | 100000 (5 × 20000) |
| `MoFang-768-XOF` | 4096 B | 118.3 k | 28.9 | 56.5 µs | 72.5 | 76335 (5 × 15267) |
| `MoFang-768-XOF` | 8192 B | 233.4 k | 28.5 | 111 µs | 73.5 | 41720 (5 × 8344) |
| `MoFang-768-XOF` | 16384 B | 463.2 k | 28.3 | 221 µs | 74.0 | 21515 (5 × 4303) |
| `MoFang-768-XOF` | 65536 B | 1.86 M | 28.3 | 886 µs | 74.0 | 5505 (5 × 1101) |
| `MoFang-1024` | 32 B | 4421 | 138.2 | 2.11 µs | 15.1 | 100000 (5 × 20000) |
| `MoFang-1024` | 128 B | 4418 | 34.5 | 2.11 µs | 60.6 | 100000 (5 × 20000) |
| `MoFang-1024` | 512 B | 16.7 k | 32.7 | 7.99 µs | 64.1 | 100000 (5 × 20000) |
| `MoFang-1024` | 1024 B | 33.0 k | 32.2 | 15.8 µs | 65.0 | 100000 (5 × 20000) |
| `MoFang-1024` | 4096 B | 117.6 k | 28.7 | 56.2 µs | 72.9 | 76895 (5 × 15379) |
| `MoFang-1024` | 8192 B | 232.5 k | 28.4 | 111 µs | 73.8 | 40790 (5 × 8158) |
| `MoFang-1024` | 16384 B | 464.2 k | 28.3 | 222 µs | 73.9 | 21090 (5 × 4218) |
| `MoFang-1024` | 65536 B | 1.85 M | 28.2 | 884 µs | 74.1 | 5100 (5 × 1020) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `MoFang-256` | hash_32 | 12721 | 1680 KiB | 1744 KiB |
| `MoFang-256` | hash_128 | 12721 | 1692 KiB | 1756 KiB |
| `MoFang-256` | hash_512 | 12721 | 1692 KiB | 1768 KiB |
| `MoFang-256` | hash_1024 | 12721 | 1668 KiB | 1760 KiB |
| `MoFang-256` | hash_4096 | 12721 | 1684 KiB | 1776 KiB |
| `MoFang-256` | hash_8192 | 12721 | 1696 KiB | 1768 KiB |
| `MoFang-256` | hash_16384 | 12721 | 1644 KiB | 1788 KiB |
| `MoFang-256` | hash_65536 | 12721 | 1748 KiB | 1896 KiB |
| `MoFang-256-XOF` | hash_32 | 12745 | 1656 KiB | 1780 KiB |
| `MoFang-256-XOF` | hash_128 | 12745 | 1672 KiB | 1736 KiB |
| `MoFang-256-XOF` | hash_512 | 12745 | 1680 KiB | 1744 KiB |
| `MoFang-256-XOF` | hash_1024 | 12745 | 1664 KiB | 1780 KiB |
| `MoFang-256-XOF` | hash_4096 | 12745 | 1688 KiB | 1776 KiB |
| `MoFang-256-XOF` | hash_8192 | 12745 | 1692 KiB | 1764 KiB |
| `MoFang-256-XOF` | hash_16384 | 12745 | 1704 KiB | 1784 KiB |
| `MoFang-256-XOF` | hash_65536 | 12745 | 1744 KiB | 1900 KiB |
| `MoFang-512` | hash_32 | 12721 | 1692 KiB | 1756 KiB |
| `MoFang-512` | hash_128 | 12721 | 1692 KiB | 1776 KiB |
| `MoFang-512` | hash_512 | 12721 | 1688 KiB | 1780 KiB |
| `MoFang-512` | hash_1024 | 12721 | 1692 KiB | 1772 KiB |
| `MoFang-512` | hash_4096 | 12721 | 1692 KiB | 1776 KiB |
| `MoFang-512` | hash_8192 | 12721 | 1684 KiB | 1796 KiB |
| `MoFang-512` | hash_16384 | 12721 | 1688 KiB | 1800 KiB |
| `MoFang-512` | hash_65536 | 12721 | 1712 KiB | 1900 KiB |
| `MoFang-768` | hash_32 | 13585 | 1660 KiB | 1784 KiB |
| `MoFang-768` | hash_128 | 13585 | 1668 KiB | 1784 KiB |
| `MoFang-768` | hash_512 | 13585 | 1676 KiB | 1740 KiB |
| `MoFang-768` | hash_1024 | 13585 | 1652 KiB | 1780 KiB |
| `MoFang-768` | hash_4096 | 13585 | 1676 KiB | 1772 KiB |
| `MoFang-768` | hash_8192 | 13585 | 1696 KiB | 1768 KiB |
| `MoFang-768` | hash_16384 | 13585 | 1704 KiB | 1784 KiB |
| `MoFang-768` | hash_65536 | 13585 | 1720 KiB | 1908 KiB |
| `MoFang-768-XOF` | hash_32 | 13977 | 1684 KiB | 1748 KiB |
| `MoFang-768-XOF` | hash_128 | 13977 | 1680 KiB | 1772 KiB |
| `MoFang-768-XOF` | hash_512 | 13977 | 1688 KiB | 1784 KiB |
| `MoFang-768-XOF` | hash_1024 | 13977 | 1696 KiB | 1768 KiB |
| `MoFang-768-XOF` | hash_4096 | 13977 | 1696 KiB | 1792 KiB |
| `MoFang-768-XOF` | hash_8192 | 13977 | 1700 KiB | 1792 KiB |
| `MoFang-768-XOF` | hash_16384 | 13977 | 1684 KiB | 1764 KiB |
| `MoFang-768-XOF` | hash_65536 | 13977 | 1752 KiB | 1900 KiB |
| `MoFang-1024` | hash_32 | 13649 | 1672 KiB | 1772 KiB |
| `MoFang-1024` | hash_128 | 13649 | 1696 KiB | 1760 KiB |
| `MoFang-1024` | hash_512 | 13649 | 1672 KiB | 1776 KiB |
| `MoFang-1024` | hash_1024 | 13649 | 1680 KiB | 1748 KiB |
| `MoFang-1024` | hash_4096 | 13649 | 1676 KiB | 1744 KiB |
| `MoFang-1024` | hash_8192 | 13649 | 1704 KiB | 1796 KiB |
| `MoFang-1024` | hash_16384 | 13649 | 1712 KiB | 1816 KiB |
| `MoFang-1024` | hash_65536 | 13649 | 1736 KiB | 1908 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `MoFang-256` | KAT log (sha256 `30b813c8e99c46bd…`) | `kat/hash-19/MoFang-256.log` |
| `MoFang-256` | timing hash_1024 | `records/hash-19/MoFang-256__hash_1024.json` |
| `MoFang-256` | timing hash_128 | `records/hash-19/MoFang-256__hash_128.json` |
| `MoFang-256` | timing hash_16384 | `records/hash-19/MoFang-256__hash_16384.json` |
| `MoFang-256` | timing hash_32 | `records/hash-19/MoFang-256__hash_32.json` |
| `MoFang-256` | timing hash_4096 | `records/hash-19/MoFang-256__hash_4096.json` |
| `MoFang-256` | timing hash_512 | `records/hash-19/MoFang-256__hash_512.json` |
| `MoFang-256` | timing hash_65536 | `records/hash-19/MoFang-256__hash_65536.json` |
| `MoFang-256` | timing hash_8192 | `records/hash-19/MoFang-256__hash_8192.json` |
| `MoFang-256-XOF` | KAT log (sha256 `9937aacba8d96bf3…`) | `kat/hash-19/MoFang-256-XOF.log` |
| `MoFang-256-XOF` | timing hash_1024 | `records/hash-19/MoFang-256-XOF__hash_1024.json` |
| `MoFang-256-XOF` | timing hash_128 | `records/hash-19/MoFang-256-XOF__hash_128.json` |
| `MoFang-256-XOF` | timing hash_16384 | `records/hash-19/MoFang-256-XOF__hash_16384.json` |
| `MoFang-256-XOF` | timing hash_32 | `records/hash-19/MoFang-256-XOF__hash_32.json` |
| `MoFang-256-XOF` | timing hash_4096 | `records/hash-19/MoFang-256-XOF__hash_4096.json` |
| `MoFang-256-XOF` | timing hash_512 | `records/hash-19/MoFang-256-XOF__hash_512.json` |
| `MoFang-256-XOF` | timing hash_65536 | `records/hash-19/MoFang-256-XOF__hash_65536.json` |
| `MoFang-256-XOF` | timing hash_8192 | `records/hash-19/MoFang-256-XOF__hash_8192.json` |
| `MoFang-512` | KAT log (sha256 `9c97fcd8cbe3437b…`) | `kat/hash-19/MoFang-512.log` |
| `MoFang-512` | timing hash_1024 | `records/hash-19/MoFang-512__hash_1024.json` |
| `MoFang-512` | timing hash_128 | `records/hash-19/MoFang-512__hash_128.json` |
| `MoFang-512` | timing hash_16384 | `records/hash-19/MoFang-512__hash_16384.json` |
| `MoFang-512` | timing hash_32 | `records/hash-19/MoFang-512__hash_32.json` |
| `MoFang-512` | timing hash_4096 | `records/hash-19/MoFang-512__hash_4096.json` |
| `MoFang-512` | timing hash_512 | `records/hash-19/MoFang-512__hash_512.json` |
| `MoFang-512` | timing hash_65536 | `records/hash-19/MoFang-512__hash_65536.json` |
| `MoFang-512` | timing hash_8192 | `records/hash-19/MoFang-512__hash_8192.json` |
| `MoFang-768` | KAT log (sha256 `43c4126512149d80…`) | `kat/hash-19/MoFang-768.log` |
| `MoFang-768` | timing hash_1024 | `records/hash-19/MoFang-768__hash_1024.json` |
| `MoFang-768` | timing hash_128 | `records/hash-19/MoFang-768__hash_128.json` |
| `MoFang-768` | timing hash_16384 | `records/hash-19/MoFang-768__hash_16384.json` |
| `MoFang-768` | timing hash_32 | `records/hash-19/MoFang-768__hash_32.json` |
| `MoFang-768` | timing hash_4096 | `records/hash-19/MoFang-768__hash_4096.json` |
| `MoFang-768` | timing hash_512 | `records/hash-19/MoFang-768__hash_512.json` |
| `MoFang-768` | timing hash_65536 | `records/hash-19/MoFang-768__hash_65536.json` |
| `MoFang-768` | timing hash_8192 | `records/hash-19/MoFang-768__hash_8192.json` |
| `MoFang-768-XOF` | KAT log (sha256 `446ca6f22b7d83a2…`) | `kat/hash-19/MoFang-768-XOF.log` |
| `MoFang-768-XOF` | timing hash_1024 | `records/hash-19/MoFang-768-XOF__hash_1024.json` |
| `MoFang-768-XOF` | timing hash_128 | `records/hash-19/MoFang-768-XOF__hash_128.json` |
| `MoFang-768-XOF` | timing hash_16384 | `records/hash-19/MoFang-768-XOF__hash_16384.json` |
| `MoFang-768-XOF` | timing hash_32 | `records/hash-19/MoFang-768-XOF__hash_32.json` |
| `MoFang-768-XOF` | timing hash_4096 | `records/hash-19/MoFang-768-XOF__hash_4096.json` |
| `MoFang-768-XOF` | timing hash_512 | `records/hash-19/MoFang-768-XOF__hash_512.json` |
| `MoFang-768-XOF` | timing hash_65536 | `records/hash-19/MoFang-768-XOF__hash_65536.json` |
| `MoFang-768-XOF` | timing hash_8192 | `records/hash-19/MoFang-768-XOF__hash_8192.json` |
| `MoFang-1024` | KAT log (sha256 `539ba564a13ca2c2…`) | `kat/hash-19/MoFang-1024.log` |
| `MoFang-1024` | timing hash_1024 | `records/hash-19/MoFang-1024__hash_1024.json` |
| `MoFang-1024` | timing hash_128 | `records/hash-19/MoFang-1024__hash_128.json` |
| `MoFang-1024` | timing hash_16384 | `records/hash-19/MoFang-1024__hash_16384.json` |
| `MoFang-1024` | timing hash_32 | `records/hash-19/MoFang-1024__hash_32.json` |
| `MoFang-1024` | timing hash_4096 | `records/hash-19/MoFang-1024__hash_4096.json` |
| `MoFang-1024` | timing hash_512 | `records/hash-19/MoFang-1024__hash_512.json` |
| `MoFang-1024` | timing hash_65536 | `records/hash-19/MoFang-1024__hash_65536.json` |
| `MoFang-1024` | timing hash_8192 | `records/hash-19/MoFang-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

