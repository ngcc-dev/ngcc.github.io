<!-- synchronized from harness: hash-27/perf_x86_1.md -->
# hash-27 The Vedak Hash Function Family — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-27` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101535609849466880.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-27.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: The Vedak Hash Function Family
- Implementation versions measured: reference
- Parameter sets: `Vedak-512`, `Vedak-768`, `Vedak-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-27/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Vedak-512` | guide | PASS |
| `Vedak-768` | guide | PASS |
| `Vedak-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Vedak-512` | 32 B | 24.7 k | 771.1 | 11.8 µs | 2.7 | 100000 (5 × 20000) |
| `Vedak-512` | 128 B | 28.3 k | 221.1 | 13.5 µs | 9.5 | 100000 (5 × 20000) |
| `Vedak-512` | 512 B | 88.1 k | 172.0 | 42.1 µs | 12.2 | 99745 (5 × 19949) |
| `Vedak-512` | 1024 B | 174.6 k | 170.5 | 83.4 µs | 12.3 | 52670 (5 × 10534) |
| `Vedak-512` | 4096 B | 658.8 k | 160.8 | 315 µs | 13.0 | 15330 (5 × 3066) |
| `Vedak-512` | 8192 B | 1.29 M | 157.3 | 616 µs | 13.3 | 7890 (5 × 1578) |
| `Vedak-512` | 16384 B | 2.57 M | 156.6 | 1.23 ms | 13.4 | 3990 (5 × 798) |
| `Vedak-512` | 65536 B | 10.10 M | 154.1 | 4.82 ms | 13.6 | 1020 (5 × 204) |
| `Vedak-768` | 32 B | 24.6 k | 768.0 | 11.7 µs | 2.7 | 100000 (5 × 20000) |
| `Vedak-768` | 128 B | 51.0 k | 398.5 | 24.4 µs | 5.3 | 100000 (5 × 20000) |
| `Vedak-768` | 512 B | 134.1 k | 261.9 | 64.1 µs | 8.0 | 69145 (5 × 13829) |
| `Vedak-768` | 1024 B | 245.7 k | 240.0 | 117 µs | 8.7 | 39325 (5 × 7865) |
| `Vedak-768` | 4096 B | 914.2 k | 223.2 | 437 µs | 9.4 | 10780 (5 × 2156) |
| `Vedak-768` | 8192 B | 1.80 M | 219.9 | 861 µs | 9.5 | 5710 (5 × 1142) |
| `Vedak-768` | 16384 B | 3.56 M | 217.3 | 1.7 ms | 9.6 | 2900 (5 × 580) |
| `Vedak-768` | 65536 B | 14.07 M | 214.7 | 6.72 ms | 9.7 | 745 (5 × 149) |
| `Vedak-1024` | 32 B | 47.6 k | 1488.5 | 22.8 µs | 1.4 | 100000 (5 × 20000) |
| `Vedak-1024` | 128 B | 97.4 k | 761.0 | 46.5 µs | 2.8 | 93485 (5 × 18697) |
| `Vedak-1024` | 512 B | 249.3 k | 486.9 | 119 µs | 4.3 | 39360 (5 × 7872) |
| `Vedak-1024` | 1024 B | 453.3 k | 442.7 | 217 µs | 4.7 | 22130 (5 × 4426) |
| `Vedak-1024` | 4096 B | 1.67 M | 408.9 | 800 µs | 5.1 | 6235 (5 × 1247) |
| `Vedak-1024` | 8192 B | 3.29 M | 402.2 | 1.57 ms | 5.2 | 3010 (5 × 602) |
| `Vedak-1024` | 16384 B | 6.52 M | 397.9 | 3.11 ms | 5.3 | 1590 (5 × 318) |
| `Vedak-1024` | 65536 B | 25.93 M | 395.7 | 12.4 ms | 5.3 | 405 (5 × 81) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Vedak-512` | hash_32 | 12601 | 1680 KiB | 1756 KiB |
| `Vedak-512` | hash_128 | 12601 | 1692 KiB | 1756 KiB |
| `Vedak-512` | hash_512 | 12601 | 1684 KiB | 1768 KiB |
| `Vedak-512` | hash_1024 | 12601 | 1672 KiB | 1784 KiB |
| `Vedak-512` | hash_4096 | 12601 | 1672 KiB | 1764 KiB |
| `Vedak-512` | hash_8192 | 12601 | 1680 KiB | 1776 KiB |
| `Vedak-512` | hash_16384 | 12601 | 1708 KiB | 1792 KiB |
| `Vedak-512` | hash_65536 | 12601 | 1752 KiB | 1904 KiB |
| `Vedak-768` | hash_32 | 12601 | 1680 KiB | 1776 KiB |
| `Vedak-768` | hash_128 | 12601 | 1688 KiB | 1776 KiB |
| `Vedak-768` | hash_512 | 12601 | 1672 KiB | 1776 KiB |
| `Vedak-768` | hash_1024 | 12601 | 1672 KiB | 1772 KiB |
| `Vedak-768` | hash_4096 | 12601 | 1672 KiB | 1764 KiB |
| `Vedak-768` | hash_8192 | 12601 | 1696 KiB | 1768 KiB |
| `Vedak-768` | hash_16384 | 12601 | 1704 KiB | 1784 KiB |
| `Vedak-768` | hash_65536 | 12601 | 1732 KiB | 1904 KiB |
| `Vedak-1024` | hash_32 | 12601 | 1672 KiB | 1736 KiB |
| `Vedak-1024` | hash_128 | 12601 | 1664 KiB | 1780 KiB |
| `Vedak-1024` | hash_512 | 12601 | 1680 KiB | 1756 KiB |
| `Vedak-1024` | hash_1024 | 12601 | 1680 KiB | 1780 KiB |
| `Vedak-1024` | hash_4096 | 12601 | 1672 KiB | 1776 KiB |
| `Vedak-1024` | hash_8192 | 12601 | 1664 KiB | 1796 KiB |
| `Vedak-1024` | hash_16384 | 12601 | 1688 KiB | 1804 KiB |
| `Vedak-1024` | hash_65536 | 12601 | 1736 KiB | 1908 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Vedak-512` | KAT log (sha256 `5c61763865a0a7ba…`) | `kat/hash-27/Vedak-512.log` |
| `Vedak-512` | timing hash_1024 | `records/hash-27/Vedak-512__hash_1024.json` |
| `Vedak-512` | timing hash_128 | `records/hash-27/Vedak-512__hash_128.json` |
| `Vedak-512` | timing hash_16384 | `records/hash-27/Vedak-512__hash_16384.json` |
| `Vedak-512` | timing hash_32 | `records/hash-27/Vedak-512__hash_32.json` |
| `Vedak-512` | timing hash_4096 | `records/hash-27/Vedak-512__hash_4096.json` |
| `Vedak-512` | timing hash_512 | `records/hash-27/Vedak-512__hash_512.json` |
| `Vedak-512` | timing hash_65536 | `records/hash-27/Vedak-512__hash_65536.json` |
| `Vedak-512` | timing hash_8192 | `records/hash-27/Vedak-512__hash_8192.json` |
| `Vedak-768` | KAT log (sha256 `d310d9c0966f44fc…`) | `kat/hash-27/Vedak-768.log` |
| `Vedak-768` | timing hash_1024 | `records/hash-27/Vedak-768__hash_1024.json` |
| `Vedak-768` | timing hash_128 | `records/hash-27/Vedak-768__hash_128.json` |
| `Vedak-768` | timing hash_16384 | `records/hash-27/Vedak-768__hash_16384.json` |
| `Vedak-768` | timing hash_32 | `records/hash-27/Vedak-768__hash_32.json` |
| `Vedak-768` | timing hash_4096 | `records/hash-27/Vedak-768__hash_4096.json` |
| `Vedak-768` | timing hash_512 | `records/hash-27/Vedak-768__hash_512.json` |
| `Vedak-768` | timing hash_65536 | `records/hash-27/Vedak-768__hash_65536.json` |
| `Vedak-768` | timing hash_8192 | `records/hash-27/Vedak-768__hash_8192.json` |
| `Vedak-1024` | KAT log (sha256 `38544b3761483697…`) | `kat/hash-27/Vedak-1024.log` |
| `Vedak-1024` | timing hash_1024 | `records/hash-27/Vedak-1024__hash_1024.json` |
| `Vedak-1024` | timing hash_128 | `records/hash-27/Vedak-1024__hash_128.json` |
| `Vedak-1024` | timing hash_16384 | `records/hash-27/Vedak-1024__hash_16384.json` |
| `Vedak-1024` | timing hash_32 | `records/hash-27/Vedak-1024__hash_32.json` |
| `Vedak-1024` | timing hash_4096 | `records/hash-27/Vedak-1024__hash_4096.json` |
| `Vedak-1024` | timing hash_512 | `records/hash-27/Vedak-1024__hash_512.json` |
| `Vedak-1024` | timing hash_65536 | `records/hash-27/Vedak-1024__hash_65536.json` |
| `Vedak-1024` | timing hash_8192 | `records/hash-27/Vedak-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

