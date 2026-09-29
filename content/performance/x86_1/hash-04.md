<!-- synchronized from harness: hash-04/perf_x86_1.md -->
# hash-04 CHAMP — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-04` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101540375996485632.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-04.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: CHAMP
- Implementation versions measured: reference
- Parameter sets: `CHAMP-512`, `CHAMP-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-04/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `CHAMP-512` | guide | PASS |
| `CHAMP-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `CHAMP-512` | 32 B | 66.9 k | 2091.7 | 32 µs | 1.0 | 10440 (5 × 2088) |
| `CHAMP-512` | 128 B | 106.4 k | 831.3 | 50.9 µs | 2.5 | 10000 (5 × 2000) |
| `CHAMP-512` | 512 B | 294.6 k | 575.3 | 141 µs | 3.6 | 8420 (5 × 1684) |
| `CHAMP-512` | 1024 B | 564.1 k | 550.8 | 269 µs | 3.8 | 6875 (5 × 1375) |
| `CHAMP-512` | 4096 B | 2.15 M | 523.8 | 1.02 ms | 4.0 | 3355 (5 × 671) |
| `CHAMP-512` | 8192 B | 4.26 M | 519.7 | 2.03 ms | 4.0 | 2010 (5 × 402) |
| `CHAMP-512` | 16384 B | 8.49 M | 518.1 | 4.06 ms | 4.0 | 1105 (5 × 221) |
| `CHAMP-512` | 65536 B | 33.76 M | 515.1 | 16.1 ms | 4.1 | 300 (5 × 60) |
| `CHAMP-1024` | 32 B | 369.9 k | 11559.2 | 177 µs | 0.2 | 3240 (5 × 648) |
| `CHAMP-1024` | 128 B | 506.0 k | 3953.2 | 242 µs | 0.5 | 3100 (5 × 620) |
| `CHAMP-1024` | 512 B | 1.06 M | 2060.7 | 504 µs | 1.0 | 2680 (5 × 536) |
| `CHAMP-1024` | 1024 B | 1.78 M | 1742.0 | 852 µs | 1.2 | 2250 (5 × 450) |
| `CHAMP-1024` | 4096 B | 6.16 M | 1503.1 | 2.94 ms | 1.4 | 1160 (5 × 232) |
| `CHAMP-1024` | 8192 B | 11.99 M | 1463.5 | 5.73 ms | 1.4 | 705 (5 × 141) |
| `CHAMP-1024` | 16384 B | 23.65 M | 1443.3 | 11.3 ms | 1.5 | 395 (5 × 79) |
| `CHAMP-1024` | 65536 B | 93.70 M | 1429.8 | 44.8 ms | 1.5 | 110 (5 × 22) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `CHAMP-512` | hash_32 | 29609 | 1692 KiB | 1772 KiB |
| `CHAMP-512` | hash_128 | 29609 | 1672 KiB | 1772 KiB |
| `CHAMP-512` | hash_512 | 29609 | 1672 KiB | 1792 KiB |
| `CHAMP-512` | hash_1024 | 29609 | 1692 KiB | 1792 KiB |
| `CHAMP-512` | hash_4096 | 29609 | 1692 KiB | 1796 KiB |
| `CHAMP-512` | hash_8192 | 29609 | 1684 KiB | 1792 KiB |
| `CHAMP-512` | hash_16384 | 29609 | 1708 KiB | 1808 KiB |
| `CHAMP-512` | hash_65536 | 29609 | 1744 KiB | 1848 KiB |
| `CHAMP-1024` | hash_32 | 47729 | 1676 KiB | 1772 KiB |
| `CHAMP-1024` | hash_128 | 47729 | 1684 KiB | 1780 KiB |
| `CHAMP-1024` | hash_512 | 47729 | 1676 KiB | 1816 KiB |
| `CHAMP-1024` | hash_1024 | 47729 | 1592 KiB | 1752 KiB |
| `CHAMP-1024` | hash_4096 | 47729 | 1696 KiB | 1792 KiB |
| `CHAMP-1024` | hash_8192 | 47729 | 1696 KiB | 1800 KiB |
| `CHAMP-1024` | hash_16384 | 47729 | 1680 KiB | 1824 KiB |
| `CHAMP-1024` | hash_65536 | 47729 | 1752 KiB | 1876 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `CHAMP-512` | KAT log (sha256 `532066ce93f9ccfa…`) | `kat/hash-04/CHAMP-512.log` |
| `CHAMP-512` | timing hash_1024 | `records/hash-04/CHAMP-512__hash_1024.json` |
| `CHAMP-512` | timing hash_128 | `records/hash-04/CHAMP-512__hash_128.json` |
| `CHAMP-512` | timing hash_16384 | `records/hash-04/CHAMP-512__hash_16384.json` |
| `CHAMP-512` | timing hash_32 | `records/hash-04/CHAMP-512__hash_32.json` |
| `CHAMP-512` | timing hash_4096 | `records/hash-04/CHAMP-512__hash_4096.json` |
| `CHAMP-512` | timing hash_512 | `records/hash-04/CHAMP-512__hash_512.json` |
| `CHAMP-512` | timing hash_65536 | `records/hash-04/CHAMP-512__hash_65536.json` |
| `CHAMP-512` | timing hash_8192 | `records/hash-04/CHAMP-512__hash_8192.json` |
| `CHAMP-1024` | KAT log (sha256 `500c8b60b0fd9ccc…`) | `kat/hash-04/CHAMP-1024.log` |
| `CHAMP-1024` | timing hash_1024 | `records/hash-04/CHAMP-1024__hash_1024.json` |
| `CHAMP-1024` | timing hash_128 | `records/hash-04/CHAMP-1024__hash_128.json` |
| `CHAMP-1024` | timing hash_16384 | `records/hash-04/CHAMP-1024__hash_16384.json` |
| `CHAMP-1024` | timing hash_32 | `records/hash-04/CHAMP-1024__hash_32.json` |
| `CHAMP-1024` | timing hash_4096 | `records/hash-04/CHAMP-1024__hash_4096.json` |
| `CHAMP-1024` | timing hash_512 | `records/hash-04/CHAMP-1024__hash_512.json` |
| `CHAMP-1024` | timing hash_65536 | `records/hash-04/CHAMP-1024__hash_65536.json` |
| `CHAMP-1024` | timing hash_8192 | `records/hash-04/CHAMP-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

