<!-- synchronized from harness: hash-06/perf_x86_1.md -->
# hash-06 Cuishen — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-06` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101539989910802432.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-06.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Cuishen
- Implementation versions measured: reference
- Parameter sets: `Cuishen-512`, `Cuishen-768`, `Cuishen-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-06/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Cuishen-512` | guide | PASS |
| `Cuishen-768` | guide | PASS |
| `Cuishen-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Cuishen-512` | 32 B | 2294 | 71.7 | 1.1 µs | 29.1 | 100000 (5 × 20000) |
| `Cuishen-512` | 128 B | 4496 | 35.1 | 2.15 µs | 59.6 | 100000 (5 × 20000) |
| `Cuishen-512` | 512 B | 11.2 k | 22.0 | 5.37 µs | 95.3 | 100000 (5 × 20000) |
| `Cuishen-512` | 1024 B | 20.2 k | 19.7 | 9.65 µs | 106.1 | 100000 (5 × 20000) |
| `Cuishen-512` | 4096 B | 73.9 k | 18.0 | 35.3 µs | 116.1 | 100000 (5 × 20000) |
| `Cuishen-512` | 8192 B | 145.3 k | 17.7 | 69.4 µs | 118.0 | 65525 (5 × 13105) |
| `Cuishen-512` | 16384 B | 290.8 k | 17.8 | 139 µs | 117.9 | 35140 (5 × 7028) |
| `Cuishen-512` | 65536 B | 1.17 M | 17.8 | 558 µs | 117.5 | 8970 (5 × 1794) |
| `Cuishen-768` | 32 B | 3119 | 97.5 | 1.49 µs | 21.4 | 100000 (5 × 20000) |
| `Cuishen-768` | 128 B | 6363 | 49.7 | 3.04 µs | 42.1 | 100000 (5 × 20000) |
| `Cuishen-768` | 512 B | 15.6 k | 30.5 | 7.47 µs | 68.5 | 100000 (5 × 20000) |
| `Cuishen-768` | 1024 B | 28.7 k | 28.0 | 13.7 µs | 74.7 | 100000 (5 × 20000) |
| `Cuishen-768` | 4096 B | 102.8 k | 25.1 | 49.1 µs | 83.4 | 84145 (5 × 16829) |
| `Cuishen-768` | 8192 B | 208.2 k | 25.4 | 99.4 µs | 82.4 | 48350 (5 × 9670) |
| `Cuishen-768` | 16384 B | 402.0 k | 24.5 | 192 µs | 85.3 | 19175 (5 × 3835) |
| `Cuishen-768` | 65536 B | 1.62 M | 24.8 | 776 µs | 84.5 | 6575 (5 × 1315) |
| `Cuishen-1024` | 32 B | 3214 | 100.4 | 1.54 µs | 20.8 | 100000 (5 × 20000) |
| `Cuishen-1024` | 128 B | 6364 | 49.7 | 3.04 µs | 42.0 | 100000 (5 × 20000) |
| `Cuishen-1024` | 512 B | 15.7 k | 30.7 | 7.52 µs | 68.1 | 100000 (5 × 20000) |
| `Cuishen-1024` | 1024 B | 28.3 k | 27.6 | 13.5 µs | 75.8 | 100000 (5 × 20000) |
| `Cuishen-1024` | 4096 B | 102.1 k | 24.9 | 48.8 µs | 83.9 | 85610 (5 × 17122) |
| `Cuishen-1024` | 8192 B | 209.5 k | 25.6 | 100 µs | 81.9 | 48695 (5 × 9739) |
| `Cuishen-1024` | 16384 B | 407.3 k | 24.9 | 195 µs | 84.2 | 25335 (5 × 5067) |
| `Cuishen-1024` | 65536 B | 1.63 M | 24.9 | 779 µs | 84.1 | 6380 (5 × 1276) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Cuishen-512` | hash_32 | 13161 | 1672 KiB | 1776 KiB |
| `Cuishen-512` | hash_128 | 13161 | 1664 KiB | 1776 KiB |
| `Cuishen-512` | hash_512 | 13161 | 1672 KiB | 1760 KiB |
| `Cuishen-512` | hash_1024 | 13161 | 1688 KiB | 1776 KiB |
| `Cuishen-512` | hash_4096 | 13161 | 1600 KiB | 1728 KiB |
| `Cuishen-512` | hash_8192 | 13161 | 1688 KiB | 1752 KiB |
| `Cuishen-512` | hash_16384 | 13161 | 1700 KiB | 1764 KiB |
| `Cuishen-512` | hash_65536 | 13161 | 1732 KiB | 1824 KiB |
| `Cuishen-768` | hash_32 | 14001 | 1632 KiB | 1764 KiB |
| `Cuishen-768` | hash_128 | 14001 | 1668 KiB | 1732 KiB |
| `Cuishen-768` | hash_512 | 14001 | 1684 KiB | 1784 KiB |
| `Cuishen-768` | hash_1024 | 14001 | 1664 KiB | 1776 KiB |
| `Cuishen-768` | hash_4096 | 14001 | 1680 KiB | 1784 KiB |
| `Cuishen-768` | hash_8192 | 14001 | 1680 KiB | 1748 KiB |
| `Cuishen-768` | hash_16384 | 14001 | 1680 KiB | 1796 KiB |
| `Cuishen-768` | hash_65536 | 14001 | 1756 KiB | 1848 KiB |
| `Cuishen-1024` | hash_32 | 13937 | 1676 KiB | 1776 KiB |
| `Cuishen-1024` | hash_128 | 13937 | 1664 KiB | 1776 KiB |
| `Cuishen-1024` | hash_512 | 13937 | 1680 KiB | 1772 KiB |
| `Cuishen-1024` | hash_1024 | 13937 | 1680 KiB | 1748 KiB |
| `Cuishen-1024` | hash_4096 | 13937 | 1676 KiB | 1768 KiB |
| `Cuishen-1024` | hash_8192 | 13937 | 1680 KiB | 1748 KiB |
| `Cuishen-1024` | hash_16384 | 13937 | 1708 KiB | 1788 KiB |
| `Cuishen-1024` | hash_65536 | 13937 | 1744 KiB | 1848 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Cuishen-512` | KAT log (sha256 `25d1b5a50608fa0a…`) | `kat/hash-06/Cuishen-512.log` |
| `Cuishen-512` | timing hash_1024 | `records/hash-06/Cuishen-512__hash_1024.json` |
| `Cuishen-512` | timing hash_128 | `records/hash-06/Cuishen-512__hash_128.json` |
| `Cuishen-512` | timing hash_16384 | `records/hash-06/Cuishen-512__hash_16384.json` |
| `Cuishen-512` | timing hash_32 | `records/hash-06/Cuishen-512__hash_32.json` |
| `Cuishen-512` | timing hash_4096 | `records/hash-06/Cuishen-512__hash_4096.json` |
| `Cuishen-512` | timing hash_512 | `records/hash-06/Cuishen-512__hash_512.json` |
| `Cuishen-512` | timing hash_65536 | `records/hash-06/Cuishen-512__hash_65536.json` |
| `Cuishen-512` | timing hash_8192 | `records/hash-06/Cuishen-512__hash_8192.json` |
| `Cuishen-768` | KAT log (sha256 `2187fd4449445d1b…`) | `kat/hash-06/Cuishen-768.log` |
| `Cuishen-768` | timing hash_1024 | `records/hash-06/Cuishen-768__hash_1024.json` |
| `Cuishen-768` | timing hash_128 | `records/hash-06/Cuishen-768__hash_128.json` |
| `Cuishen-768` | timing hash_16384 | `records/hash-06/Cuishen-768__hash_16384.json` |
| `Cuishen-768` | timing hash_32 | `records/hash-06/Cuishen-768__hash_32.json` |
| `Cuishen-768` | timing hash_4096 | `records/hash-06/Cuishen-768__hash_4096.json` |
| `Cuishen-768` | timing hash_512 | `records/hash-06/Cuishen-768__hash_512.json` |
| `Cuishen-768` | timing hash_65536 | `records/hash-06/Cuishen-768__hash_65536.json` |
| `Cuishen-768` | timing hash_8192 | `records/hash-06/Cuishen-768__hash_8192.json` |
| `Cuishen-1024` | KAT log (sha256 `6b71ef5bcff00c0c…`) | `kat/hash-06/Cuishen-1024.log` |
| `Cuishen-1024` | timing hash_1024 | `records/hash-06/Cuishen-1024__hash_1024.json` |
| `Cuishen-1024` | timing hash_128 | `records/hash-06/Cuishen-1024__hash_128.json` |
| `Cuishen-1024` | timing hash_16384 | `records/hash-06/Cuishen-1024__hash_16384.json` |
| `Cuishen-1024` | timing hash_32 | `records/hash-06/Cuishen-1024__hash_32.json` |
| `Cuishen-1024` | timing hash_4096 | `records/hash-06/Cuishen-1024__hash_4096.json` |
| `Cuishen-1024` | timing hash_512 | `records/hash-06/Cuishen-1024__hash_512.json` |
| `Cuishen-1024` | timing hash_65536 | `records/hash-06/Cuishen-1024__hash_65536.json` |
| `Cuishen-1024` | timing hash_8192 | `records/hash-06/Cuishen-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

