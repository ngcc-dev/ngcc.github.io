<!-- synchronized from harness: hash-12/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-12</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101538722543128576.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-12.md">arm_1</a></p>

# hash-12 Iphe — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Iphe
- Implementation versions measured: reference
- Parameter sets: `Iphe-512`, `Iphe-768`, `Iphe-1024`
- Security evaluation: [hash-12 report](../../reports/hash-12.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-12/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Iphe-512` | guide | PASS |
| `Iphe-768` | guide | PASS |
| `Iphe-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Iphe-512` | 32 B | 18.5 k | 576.8 | 8.82 µs | 3.6 | 100000 (5 × 20000) |
| `Iphe-512` | 128 B | 19.0 k | 148.7 | 9.1 µs | 14.1 | 100000 (5 × 20000) |
| `Iphe-512` | 512 B | 49.4 k | 96.5 | 23.6 µs | 21.7 | 100000 (5 × 20000) |
| `Iphe-512` | 1024 B | 94.1 k | 91.9 | 45 µs | 22.8 | 82845 (5 × 16569) |
| `Iphe-512` | 4096 B | 351.6 k | 85.8 | 168 µs | 24.4 | 27570 (5 × 5514) |
| `Iphe-512` | 8192 B | 682.9 k | 83.4 | 326 µs | 25.1 | 14545 (5 × 2909) |
| `Iphe-512` | 16384 B | 1.37 M | 83.3 | 652 µs | 25.1 | 7500 (5 × 1500) |
| `Iphe-512` | 65536 B | 5.40 M | 82.4 | 2.61 ms | 25.1 | 1910 (5 × 382) |
| `Iphe-768` | 32 B | 17.7 k | 554.3 | 8.47 µs | 3.8 | 100000 (5 × 20000) |
| `Iphe-768` | 128 B | 18.6 k | 145.5 | 8.9 µs | 14.4 | 100000 (5 × 20000) |
| `Iphe-768` | 512 B | 62.8 k | 122.6 | 30 µs | 17.1 | 100000 (5 × 20000) |
| `Iphe-768` | 1024 B | 108.0 k | 105.5 | 51.6 µs | 19.8 | 73845 (5 × 14769) |
| `Iphe-768` | 4096 B | 407.4 k | 99.5 | 195 µs | 21.0 | 23390 (5 × 4678) |
| `Iphe-768` | 8192 B | 808.9 k | 98.7 | 386 µs | 21.2 | 12230 (5 × 2446) |
| `Iphe-768` | 16384 B | 1.62 M | 98.8 | 773 µs | 21.2 | 6240 (5 × 1248) |
| `Iphe-768` | 65536 B | 6.48 M | 98.9 | 3.13 ms | 20.9 | 1595 (5 × 319) |
| `Iphe-1024` | 32 B | 17.1 k | 535.7 | 8.19 µs | 3.9 | 100000 (5 × 20000) |
| `Iphe-1024` | 128 B | 31.4 k | 245.4 | 15 µs | 8.5 | 100000 (5 × 20000) |
| `Iphe-1024` | 512 B | 76.2 k | 148.7 | 36.4 µs | 14.1 | 100000 (5 × 20000) |
| `Iphe-1024` | 1024 B | 135.7 k | 132.5 | 64.8 µs | 15.8 | 63760 (5 × 12752) |
| `Iphe-1024` | 4096 B | 520.7 k | 127.1 | 249 µs | 16.5 | 19085 (5 × 3817) |
| `Iphe-1024` | 8192 B | 1.02 M | 124.9 | 489 µs | 16.8 | 9880 (5 × 1976) |
| `Iphe-1024` | 16384 B | 2.03 M | 123.8 | 969 µs | 16.9 | 5035 (5 × 1007) |
| `Iphe-1024` | 65536 B | 8.11 M | 123.8 | 3.9 ms | 16.8 | 1245 (5 × 249) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Iphe-512` | hash_32 | 12097 | 1692 KiB | 1760 KiB |
| `Iphe-512` | hash_128 | 12097 | 1688 KiB | 1776 KiB |
| `Iphe-512` | hash_512 | 12097 | 1672 KiB | 1772 KiB |
| `Iphe-512` | hash_1024 | 12097 | 1672 KiB | 1772 KiB |
| `Iphe-512` | hash_4096 | 12097 | 1684 KiB | 1760 KiB |
| `Iphe-512` | hash_8192 | 12097 | 1672 KiB | 1780 KiB |
| `Iphe-512` | hash_16384 | 12097 | 1700 KiB | 1792 KiB |
| `Iphe-512` | hash_65536 | 12097 | 1752 KiB | 1820 KiB |
| `Iphe-768` | hash_32 | 12161 | 1680 KiB | 1744 KiB |
| `Iphe-768` | hash_128 | 12161 | 1680 KiB | 1768 KiB |
| `Iphe-768` | hash_512 | 12161 | 1692 KiB | 1756 KiB |
| `Iphe-768` | hash_1024 | 12161 | 1688 KiB | 1760 KiB |
| `Iphe-768` | hash_4096 | 12161 | 1676 KiB | 1764 KiB |
| `Iphe-768` | hash_8192 | 12161 | 1676 KiB | 1740 KiB |
| `Iphe-768` | hash_16384 | 12161 | 1680 KiB | 1788 KiB |
| `Iphe-768` | hash_65536 | 12161 | 1752 KiB | 1816 KiB |
| `Iphe-1024` | hash_32 | 12289 | 1684 KiB | 1748 KiB |
| `Iphe-1024` | hash_128 | 12289 | 1644 KiB | 1772 KiB |
| `Iphe-1024` | hash_512 | 12289 | 1668 KiB | 1780 KiB |
| `Iphe-1024` | hash_1024 | 12289 | 1684 KiB | 1748 KiB |
| `Iphe-1024` | hash_4096 | 12289 | 1660 KiB | 1784 KiB |
| `Iphe-1024` | hash_8192 | 12289 | 1676 KiB | 1764 KiB |
| `Iphe-1024` | hash_16384 | 12289 | 1708 KiB | 1792 KiB |
| `Iphe-1024` | hash_65536 | 12289 | 1736 KiB | 1800 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Iphe-512` | KAT log (sha256 `f7847fcb832f9f40…`) | `kat/hash-12/Iphe-512.log` |
| `Iphe-512` | timing hash_1024 | `records/hash-12/Iphe-512__hash_1024.json` |
| `Iphe-512` | timing hash_128 | `records/hash-12/Iphe-512__hash_128.json` |
| `Iphe-512` | timing hash_16384 | `records/hash-12/Iphe-512__hash_16384.json` |
| `Iphe-512` | timing hash_32 | `records/hash-12/Iphe-512__hash_32.json` |
| `Iphe-512` | timing hash_4096 | `records/hash-12/Iphe-512__hash_4096.json` |
| `Iphe-512` | timing hash_512 | `records/hash-12/Iphe-512__hash_512.json` |
| `Iphe-512` | timing hash_65536 | `records/hash-12/Iphe-512__hash_65536.json` |
| `Iphe-512` | timing hash_8192 | `records/hash-12/Iphe-512__hash_8192.json` |
| `Iphe-768` | KAT log (sha256 `bc720d53190324b6…`) | `kat/hash-12/Iphe-768.log` |
| `Iphe-768` | timing hash_1024 | `records/hash-12/Iphe-768__hash_1024.json` |
| `Iphe-768` | timing hash_128 | `records/hash-12/Iphe-768__hash_128.json` |
| `Iphe-768` | timing hash_16384 | `records/hash-12/Iphe-768__hash_16384.json` |
| `Iphe-768` | timing hash_32 | `records/hash-12/Iphe-768__hash_32.json` |
| `Iphe-768` | timing hash_4096 | `records/hash-12/Iphe-768__hash_4096.json` |
| `Iphe-768` | timing hash_512 | `records/hash-12/Iphe-768__hash_512.json` |
| `Iphe-768` | timing hash_65536 | `records/hash-12/Iphe-768__hash_65536.json` |
| `Iphe-768` | timing hash_8192 | `records/hash-12/Iphe-768__hash_8192.json` |
| `Iphe-1024` | KAT log (sha256 `58a1e04f5511b5a4…`) | `kat/hash-12/Iphe-1024.log` |
| `Iphe-1024` | timing hash_1024 | `records/hash-12/Iphe-1024__hash_1024.json` |
| `Iphe-1024` | timing hash_128 | `records/hash-12/Iphe-1024__hash_128.json` |
| `Iphe-1024` | timing hash_16384 | `records/hash-12/Iphe-1024__hash_16384.json` |
| `Iphe-1024` | timing hash_32 | `records/hash-12/Iphe-1024__hash_32.json` |
| `Iphe-1024` | timing hash_4096 | `records/hash-12/Iphe-1024__hash_4096.json` |
| `Iphe-1024` | timing hash_512 | `records/hash-12/Iphe-1024__hash_512.json` |
| `Iphe-1024` | timing hash_65536 | `records/hash-12/Iphe-1024__hash_65536.json` |
| `Iphe-1024` | timing hash_8192 | `records/hash-12/Iphe-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

