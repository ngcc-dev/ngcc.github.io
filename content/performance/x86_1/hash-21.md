<!-- synchronized from harness: hash-21/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-21</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-21.md">arm_1</a></p>

# hash-21 Neulaser — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Neulaser
- Implementation versions measured: reference
- Parameter sets: `Neulaser-512`, `Neulaser-768`, `Neulaser-1024`
- Security evaluation: [hash-21 report](../../reports/hash-21.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101536800629149696.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-21/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Neulaser-512` | guide | PASS |
| `Neulaser-768` | guide | PASS |
| `Neulaser-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Neulaser-512` | 32 B | 16.7 k | 520.5 | 7.96 µs | 4.0 | 100000 (5 × 20000) |
| `Neulaser-512` | 128 B | 30.7 k | 239.8 | 14.7 µs | 8.7 | 100000 (5 × 20000) |
| `Neulaser-512` | 512 B | 73.8 k | 144.1 | 35.2 µs | 14.5 | 100000 (5 × 20000) |
| `Neulaser-512` | 1024 B | 129.4 k | 126.4 | 61.8 µs | 16.6 | 72745 (5 × 14549) |
| `Neulaser-512` | 4096 B | 495.8 k | 121.1 | 237 µs | 17.3 | 20625 (5 × 4125) |
| `Neulaser-512` | 8192 B | 975.6 k | 119.1 | 466 µs | 17.6 | 10590 (5 × 2118) |
| `Neulaser-512` | 16384 B | 1.94 M | 118.3 | 926 µs | 17.7 | 5375 (5 × 1075) |
| `Neulaser-512` | 65536 B | 7.72 M | 117.7 | 3.69 ms | 17.8 | 1355 (5 × 271) |
| `Neulaser-768` | 32 B | 21.5 k | 672.6 | 10.3 µs | 3.1 | 100000 (5 × 20000) |
| `Neulaser-768` | 128 B | 21.5 k | 168.0 | 10.3 µs | 12.5 | 100000 (5 × 20000) |
| `Neulaser-768` | 512 B | 76.7 k | 149.9 | 36.7 µs | 14.0 | 100000 (5 × 20000) |
| `Neulaser-768` | 1024 B | 131.9 k | 128.8 | 63 µs | 16.3 | 71265 (5 × 14253) |
| `Neulaser-768` | 4096 B | 517.7 k | 126.4 | 247 µs | 16.6 | 19670 (5 × 3934) |
| `Neulaser-768` | 8192 B | 995.6 k | 121.5 | 476 µs | 17.2 | 10395 (5 × 2079) |
| `Neulaser-768` | 16384 B | 1.99 M | 121.3 | 950 µs | 17.3 | 5235 (5 × 1047) |
| `Neulaser-768` | 65536 B | 7.94 M | 121.2 | 3.79 ms | 17.3 | 1315 (5 × 263) |
| `Neulaser-1024` | 32 B | 26.6 k | 830.0 | 12.7 µs | 2.5 | 100000 (5 × 20000) |
| `Neulaser-1024` | 128 B | 26.7 k | 208.9 | 12.8 µs | 10.0 | 100000 (5 × 20000) |
| `Neulaser-1024` | 512 B | 71.0 k | 138.7 | 33.9 µs | 15.1 | 100000 (5 × 20000) |
| `Neulaser-1024` | 1024 B | 137.6 k | 134.3 | 65.7 µs | 15.6 | 67495 (5 × 13499) |
| `Neulaser-1024` | 4096 B | 515.7 k | 125.9 | 246 µs | 16.6 | 19820 (5 × 3964) |
| `Neulaser-1024` | 8192 B | 1.00 M | 122.4 | 479 µs | 17.1 | 10140 (5 × 2028) |
| `Neulaser-1024` | 16384 B | 2.00 M | 122.1 | 956 µs | 17.1 | 5140 (5 × 1028) |
| `Neulaser-1024` | 65536 B | 7.92 M | 120.9 | 3.79 ms | 17.3 | 1280 (5 × 256) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Neulaser-512` | hash_32 | 13617 | 1664 KiB | 1768 KiB |
| `Neulaser-512` | hash_128 | 13617 | 1688 KiB | 1780 KiB |
| `Neulaser-512` | hash_512 | 13617 | 1696 KiB | 1784 KiB |
| `Neulaser-512` | hash_1024 | 13617 | 1668 KiB | 1784 KiB |
| `Neulaser-512` | hash_4096 | 13617 | 1696 KiB | 1784 KiB |
| `Neulaser-512` | hash_8192 | 13617 | 1652 KiB | 1780 KiB |
| `Neulaser-512` | hash_16384 | 13617 | 1712 KiB | 1796 KiB |
| `Neulaser-512` | hash_65536 | 13617 | 1740 KiB | 1804 KiB |
| `Neulaser-768` | hash_32 | 13553 | 1696 KiB | 1760 KiB |
| `Neulaser-768` | hash_128 | 13553 | 1676 KiB | 1740 KiB |
| `Neulaser-768` | hash_512 | 13553 | 1684 KiB | 1748 KiB |
| `Neulaser-768` | hash_1024 | 13553 | 1660 KiB | 1784 KiB |
| `Neulaser-768` | hash_4096 | 13553 | 1676 KiB | 1740 KiB |
| `Neulaser-768` | hash_8192 | 13553 | 1684 KiB | 1780 KiB |
| `Neulaser-768` | hash_16384 | 13553 | 1708 KiB | 1772 KiB |
| `Neulaser-768` | hash_65536 | 13553 | 1748 KiB | 1812 KiB |
| `Neulaser-1024` | hash_32 | 13953 | 1696 KiB | 1760 KiB |
| `Neulaser-1024` | hash_128 | 13953 | 1692 KiB | 1756 KiB |
| `Neulaser-1024` | hash_512 | 13953 | 1684 KiB | 1748 KiB |
| `Neulaser-1024` | hash_1024 | 13953 | 1688 KiB | 1752 KiB |
| `Neulaser-1024` | hash_4096 | 13953 | 1660 KiB | 1784 KiB |
| `Neulaser-1024` | hash_8192 | 13953 | 1680 KiB | 1772 KiB |
| `Neulaser-1024` | hash_16384 | 13953 | 1696 KiB | 1796 KiB |
| `Neulaser-1024` | hash_65536 | 13953 | 1752 KiB | 1816 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Neulaser-512` | KAT log (sha256 `e6d058c909153413…`) | `kat/hash-21/Neulaser-512.log` |
| `Neulaser-512` | timing hash_1024 | `records/hash-21/Neulaser-512__hash_1024.json` |
| `Neulaser-512` | timing hash_128 | `records/hash-21/Neulaser-512__hash_128.json` |
| `Neulaser-512` | timing hash_16384 | `records/hash-21/Neulaser-512__hash_16384.json` |
| `Neulaser-512` | timing hash_32 | `records/hash-21/Neulaser-512__hash_32.json` |
| `Neulaser-512` | timing hash_4096 | `records/hash-21/Neulaser-512__hash_4096.json` |
| `Neulaser-512` | timing hash_512 | `records/hash-21/Neulaser-512__hash_512.json` |
| `Neulaser-512` | timing hash_65536 | `records/hash-21/Neulaser-512__hash_65536.json` |
| `Neulaser-512` | timing hash_8192 | `records/hash-21/Neulaser-512__hash_8192.json` |
| `Neulaser-768` | KAT log (sha256 `aec7e5c434763818…`) | `kat/hash-21/Neulaser-768.log` |
| `Neulaser-768` | timing hash_1024 | `records/hash-21/Neulaser-768__hash_1024.json` |
| `Neulaser-768` | timing hash_128 | `records/hash-21/Neulaser-768__hash_128.json` |
| `Neulaser-768` | timing hash_16384 | `records/hash-21/Neulaser-768__hash_16384.json` |
| `Neulaser-768` | timing hash_32 | `records/hash-21/Neulaser-768__hash_32.json` |
| `Neulaser-768` | timing hash_4096 | `records/hash-21/Neulaser-768__hash_4096.json` |
| `Neulaser-768` | timing hash_512 | `records/hash-21/Neulaser-768__hash_512.json` |
| `Neulaser-768` | timing hash_65536 | `records/hash-21/Neulaser-768__hash_65536.json` |
| `Neulaser-768` | timing hash_8192 | `records/hash-21/Neulaser-768__hash_8192.json` |
| `Neulaser-1024` | KAT log (sha256 `c4cfa9c6a3c8ec59…`) | `kat/hash-21/Neulaser-1024.log` |
| `Neulaser-1024` | timing hash_1024 | `records/hash-21/Neulaser-1024__hash_1024.json` |
| `Neulaser-1024` | timing hash_128 | `records/hash-21/Neulaser-1024__hash_128.json` |
| `Neulaser-1024` | timing hash_16384 | `records/hash-21/Neulaser-1024__hash_16384.json` |
| `Neulaser-1024` | timing hash_32 | `records/hash-21/Neulaser-1024__hash_32.json` |
| `Neulaser-1024` | timing hash_4096 | `records/hash-21/Neulaser-1024__hash_4096.json` |
| `Neulaser-1024` | timing hash_512 | `records/hash-21/Neulaser-1024__hash_512.json` |
| `Neulaser-1024` | timing hash_65536 | `records/hash-21/Neulaser-1024__hash_65536.json` |
| `Neulaser-1024` | timing hash_8192 | `records/hash-21/Neulaser-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

