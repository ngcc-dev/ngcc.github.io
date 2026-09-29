<!-- synchronized from harness: hash-13/perf_x86_1.md -->
# hash-13 JuziHash — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-13` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101538489901862912.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-13.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: JuziHash
- Implementation versions measured: reference
- Parameter sets: `JuziHash-512`, `JuziHash-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-13/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `JuziHash-512` | guide | PASS |
| `JuziHash-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `JuziHash-512` | 32 B | 132.9 k | 4152.1 | 63.5 µs | 0.5 | 68640 (5 × 13728) |
| `JuziHash-512` | 128 B | 133.4 k | 1042.1 | 63.7 µs | 2.0 | 69125 (5 × 13825) |
| `JuziHash-512` | 512 B | 266.2 k | 520.0 | 127 µs | 4.0 | 34450 (5 × 6890) |
| `JuziHash-512` | 1024 B | 443.3 k | 432.9 | 212 µs | 4.8 | 22525 (5 × 4505) |
| `JuziHash-512` | 4096 B | 1.51 M | 368.4 | 721 µs | 5.7 | 6820 (5 × 1364) |
| `JuziHash-512` | 8192 B | 2.93 M | 358.1 | 1.4 ms | 5.8 | 3520 (5 × 704) |
| `JuziHash-512` | 16384 B | 5.77 M | 352.2 | 2.76 ms | 5.9 | 1815 (5 × 363) |
| `JuziHash-512` | 65536 B | 22.84 M | 348.6 | 10.9 ms | 6.0 | 455 (5 × 91) |
| `JuziHash-1024` | 32 B | 133.4 k | 4169.4 | 63.7 µs | 0.5 | 68795 (5 × 13759) |
| `JuziHash-1024` | 128 B | 133.7 k | 1044.3 | 63.9 µs | 2.0 | 69810 (5 × 13962) |
| `JuziHash-1024` | 512 B | 266.4 k | 520.4 | 127 µs | 4.0 | 36565 (5 × 7313) |
| `JuziHash-1024` | 1024 B | 443.1 k | 432.8 | 212 µs | 4.8 | 22555 (5 × 4511) |
| `JuziHash-1024` | 4096 B | 1.51 M | 368.1 | 720 µs | 5.7 | 6795 (5 × 1359) |
| `JuziHash-1024` | 8192 B | 2.93 M | 357.2 | 1.4 ms | 5.9 | 3520 (5 × 704) |
| `JuziHash-1024` | 16384 B | 5.77 M | 352.0 | 2.75 ms | 5.9 | 1795 (5 × 359) |
| `JuziHash-1024` | 65536 B | 22.81 M | 348.1 | 10.9 ms | 6.0 | 455 (5 × 91) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `JuziHash-512` | hash_32 | 12513 | 1692 KiB | 1776 KiB |
| `JuziHash-512` | hash_128 | 12513 | 1660 KiB | 1756 KiB |
| `JuziHash-512` | hash_512 | 12513 | 1688 KiB | 1776 KiB |
| `JuziHash-512` | hash_1024 | 12513 | 1652 KiB | 1776 KiB |
| `JuziHash-512` | hash_4096 | 12513 | 1692 KiB | 1756 KiB |
| `JuziHash-512` | hash_8192 | 12513 | 1700 KiB | 1764 KiB |
| `JuziHash-512` | hash_16384 | 12513 | 1680 KiB | 1744 KiB |
| `JuziHash-512` | hash_65536 | 12513 | 1736 KiB | 1836 KiB |
| `JuziHash-1024` | hash_32 | 12849 | 1664 KiB | 1768 KiB |
| `JuziHash-1024` | hash_128 | 12849 | 1692 KiB | 1780 KiB |
| `JuziHash-1024` | hash_512 | 12849 | 1688 KiB | 1760 KiB |
| `JuziHash-1024` | hash_1024 | 12849 | 1664 KiB | 1776 KiB |
| `JuziHash-1024` | hash_4096 | 12849 | 1676 KiB | 1776 KiB |
| `JuziHash-1024` | hash_8192 | 12849 | 1676 KiB | 1788 KiB |
| `JuziHash-1024` | hash_16384 | 12849 | 1708 KiB | 1784 KiB |
| `JuziHash-1024` | hash_65536 | 12849 | 1732 KiB | 1796 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `JuziHash-512` | KAT log (sha256 `030e646888072c36…`) | `kat/hash-13/JuziHash-512.log` |
| `JuziHash-512` | timing hash_1024 | `records/hash-13/JuziHash-512__hash_1024.json` |
| `JuziHash-512` | timing hash_128 | `records/hash-13/JuziHash-512__hash_128.json` |
| `JuziHash-512` | timing hash_16384 | `records/hash-13/JuziHash-512__hash_16384.json` |
| `JuziHash-512` | timing hash_32 | `records/hash-13/JuziHash-512__hash_32.json` |
| `JuziHash-512` | timing hash_4096 | `records/hash-13/JuziHash-512__hash_4096.json` |
| `JuziHash-512` | timing hash_512 | `records/hash-13/JuziHash-512__hash_512.json` |
| `JuziHash-512` | timing hash_65536 | `records/hash-13/JuziHash-512__hash_65536.json` |
| `JuziHash-512` | timing hash_8192 | `records/hash-13/JuziHash-512__hash_8192.json` |
| `JuziHash-1024` | KAT log (sha256 `f70de1f51b6f0958…`) | `kat/hash-13/JuziHash-1024.log` |
| `JuziHash-1024` | timing hash_1024 | `records/hash-13/JuziHash-1024__hash_1024.json` |
| `JuziHash-1024` | timing hash_128 | `records/hash-13/JuziHash-1024__hash_128.json` |
| `JuziHash-1024` | timing hash_16384 | `records/hash-13/JuziHash-1024__hash_16384.json` |
| `JuziHash-1024` | timing hash_32 | `records/hash-13/JuziHash-1024__hash_32.json` |
| `JuziHash-1024` | timing hash_4096 | `records/hash-13/JuziHash-1024__hash_4096.json` |
| `JuziHash-1024` | timing hash_512 | `records/hash-13/JuziHash-1024__hash_512.json` |
| `JuziHash-1024` | timing hash_65536 | `records/hash-13/JuziHash-1024__hash_65536.json` |
| `JuziHash-1024` | timing hash_8192 | `records/hash-13/JuziHash-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

