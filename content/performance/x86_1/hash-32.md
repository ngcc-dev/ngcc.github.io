<!-- synchronized from harness: hash-32/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-32</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-32.md">arm_1</a></p>

# hash-32 The ZC-EDMC Hash Function — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: The ZC-EDMC Hash Function
- Implementation versions measured: reference
- Parameter sets: `ZC-EDMC-1280-512`, `ZC-EDMC-1280-768`, `ZC-EDMC-1280-1024`, `ZC-EDMC-1536-512`, `ZC-EDMC-1536-768`, `ZC-EDMC-1536-1024`
- Security evaluation: [hash-32 report](../../reports/hash-32.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101534201922277376.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-32/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `ZC-EDMC-1280-512` | guide | PASS |
| `ZC-EDMC-1280-768` | guide | PASS |
| `ZC-EDMC-1280-1024` | guide | PASS |
| `ZC-EDMC-1536-512` | guide | PASS |
| `ZC-EDMC-1536-768` | guide | PASS |
| `ZC-EDMC-1536-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `ZC-EDMC-1280-512` | 32 B | 1235 | 38.6 | 591 ns | 54.1 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-512` | 128 B | 1760 | 13.7 | 843 ns | 151.9 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-512` | 512 B | 3831 | 7.5 | 1.83 µs | 279.3 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-512` | 1024 B | 7371 | 7.2 | 3.53 µs | 290.5 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-512` | 4096 B | 27.6 k | 6.7 | 13.2 µs | 310.9 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-512` | 8192 B | 55.0 k | 6.7 | 26.3 µs | 312.0 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-512` | 16384 B | 108.6 k | 6.6 | 51.9 µs | 315.9 | 85650 (5 × 17130) |
| `ZC-EDMC-1280-512` | 65536 B | 431.8 k | 6.6 | 206 µs | 317.7 | 23885 (5 × 4777) |
| `ZC-EDMC-1280-768` | 32 B | 1539 | 48.1 | 737 ns | 43.4 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-768` | 128 B | 2880 | 22.5 | 1.38 µs | 92.9 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-768` | 512 B | 6995 | 13.7 | 3.34 µs | 153.1 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-768` | 1024 B | 12.3 k | 12.0 | 5.86 µs | 174.8 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-768` | 4096 B | 44.1 k | 10.8 | 21.1 µs | 194.5 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-768` | 8192 B | 85.9 k | 10.5 | 41 µs | 199.7 | 87100 (5 × 17420) |
| `ZC-EDMC-1280-768` | 16384 B | 170.7 k | 10.4 | 81.5 µs | 200.9 | 57000 (5 × 11400) |
| `ZC-EDMC-1280-768` | 65536 B | 679.1 k | 10.4 | 324 µs | 202.0 | 15260 (5 × 3052) |
| `ZC-EDMC-1280-1024` | 32 B | 4252 | 132.9 | 2.03 µs | 15.7 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-1024` | 128 B | 6831 | 53.4 | 3.27 µs | 39.2 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-1024` | 512 B | 16.3 k | 31.8 | 7.77 µs | 65.9 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-1024` | 1024 B | 28.0 k | 27.4 | 13.4 µs | 76.5 | 100000 (5 × 20000) |
| `ZC-EDMC-1280-1024` | 4096 B | 102.2 k | 25.0 | 48.8 µs | 83.9 | 90070 (5 × 18014) |
| `ZC-EDMC-1280-1024` | 8192 B | 200.8 k | 24.5 | 95.9 µs | 85.4 | 29615 (5 × 5923) |
| `ZC-EDMC-1280-1024` | 16384 B | 399.1 k | 24.4 | 191 µs | 85.9 | 25640 (5 × 5128) |
| `ZC-EDMC-1280-1024` | 65536 B | 1.59 M | 24.3 | 760 µs | 86.2 | 5340 (5 × 1068) |
| `ZC-EDMC-1536-512` | 32 B | 1939 | 60.6 | 929 ns | 34.4 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-512` | 128 B | 3195 | 25.0 | 1.53 µs | 83.6 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-512` | 512 B | 6287 | 12.3 | 3.01 µs | 170.0 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-512` | 1024 B | 10.4 k | 10.2 | 4.98 µs | 205.6 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-512` | 4096 B | 39.0 k | 9.5 | 18.6 µs | 219.8 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-512` | 8192 B | 76.0 k | 9.3 | 36.3 µs | 225.5 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-512` | 16384 B | 149.5 k | 9.1 | 71.5 µs | 229.3 | 64060 (5 × 12812) |
| `ZC-EDMC-1536-512` | 65536 B | 594.6 k | 9.1 | 284 µs | 230.5 | 17110 (5 × 3422) |
| `ZC-EDMC-1536-768` | 32 B | 2715 | 84.8 | 1.3 µs | 24.6 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-768` | 128 B | 3714 | 29.0 | 1.78 µs | 71.8 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-768` | 512 B | 7818 | 15.3 | 3.75 µs | 136.6 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-768` | 1024 B | 14.5 k | 14.1 | 6.94 µs | 147.5 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-768` | 4096 B | 52.6 k | 12.8 | 25.2 µs | 162.6 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-768` | 8192 B | 103.9 k | 12.7 | 49.8 µs | 164.6 | 87790 (5 × 17558) |
| `ZC-EDMC-1536-768` | 16384 B | 204.5 k | 12.5 | 98 µs | 167.2 | 46100 (5 × 9220) |
| `ZC-EDMC-1536-768` | 65536 B | 809.0 k | 12.3 | 388 µs | 169.1 | 12705 (5 × 2541) |
| `ZC-EDMC-1536-1024` | 32 B | 3472 | 108.5 | 1.66 µs | 19.3 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-1024` | 128 B | 5770 | 45.1 | 2.76 µs | 46.3 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-1024` | 512 B | 13.5 k | 26.3 | 6.44 µs | 79.5 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-1024` | 1024 B | 23.2 k | 22.6 | 11.1 µs | 92.3 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-1024` | 4096 B | 82.9 k | 20.2 | 39.7 µs | 103.2 | 100000 (5 × 20000) |
| `ZC-EDMC-1536-1024` | 8192 B | 162.0 k | 19.8 | 77.6 µs | 105.6 | 58930 (5 × 11786) |
| `ZC-EDMC-1536-1024` | 16384 B | 320.6 k | 19.6 | 154 µs | 106.7 | 31250 (5 × 6250) |
| `ZC-EDMC-1536-1024` | 65536 B | 1.27 M | 19.5 | 611 µs | 107.3 | 7760 (5 × 1552) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `ZC-EDMC-1280-512` | hash_32 | 15365 | 1656 KiB | 1780 KiB |
| `ZC-EDMC-1280-512` | hash_128 | 15365 | 1696 KiB | 1760 KiB |
| `ZC-EDMC-1280-512` | hash_512 | 15365 | 1664 KiB | 1732 KiB |
| `ZC-EDMC-1280-512` | hash_1024 | 15365 | 1676 KiB | 1780 KiB |
| `ZC-EDMC-1280-512` | hash_4096 | 15365 | 1700 KiB | 1776 KiB |
| `ZC-EDMC-1280-512` | hash_8192 | 15365 | 1700 KiB | 1772 KiB |
| `ZC-EDMC-1280-512` | hash_16384 | 15365 | 1692 KiB | 1756 KiB |
| `ZC-EDMC-1280-512` | hash_65536 | 15365 | 1760 KiB | 1844 KiB |
| `ZC-EDMC-1280-768` | hash_32 | 15365 | 1668 KiB | 1760 KiB |
| `ZC-EDMC-1280-768` | hash_128 | 15365 | 1692 KiB | 1772 KiB |
| `ZC-EDMC-1280-768` | hash_512 | 15365 | 1696 KiB | 1780 KiB |
| `ZC-EDMC-1280-768` | hash_1024 | 15365 | 1676 KiB | 1780 KiB |
| `ZC-EDMC-1280-768` | hash_4096 | 15365 | 1676 KiB | 1740 KiB |
| `ZC-EDMC-1280-768` | hash_8192 | 15365 | 1656 KiB | 1784 KiB |
| `ZC-EDMC-1280-768` | hash_16384 | 15365 | 1708 KiB | 1772 KiB |
| `ZC-EDMC-1280-768` | hash_65536 | 15365 | 1756 KiB | 1844 KiB |
| `ZC-EDMC-1280-1024` | hash_32 | 15365 | 1672 KiB | 1736 KiB |
| `ZC-EDMC-1280-1024` | hash_128 | 15365 | 1688 KiB | 1776 KiB |
| `ZC-EDMC-1280-1024` | hash_512 | 15365 | 1664 KiB | 1776 KiB |
| `ZC-EDMC-1280-1024` | hash_1024 | 15365 | 1676 KiB | 1740 KiB |
| `ZC-EDMC-1280-1024` | hash_4096 | 15365 | 1696 KiB | 1784 KiB |
| `ZC-EDMC-1280-1024` | hash_8192 | 15365 | 1692 KiB | 1788 KiB |
| `ZC-EDMC-1280-1024` | hash_16384 | 15365 | 1700 KiB | 1764 KiB |
| `ZC-EDMC-1280-1024` | hash_65536 | 15365 | 1748 KiB | 1848 KiB |
| `ZC-EDMC-1536-512` | hash_32 | 23933 | 1700 KiB | 1780 KiB |
| `ZC-EDMC-1536-512` | hash_128 | 23933 | 1704 KiB | 1792 KiB |
| `ZC-EDMC-1536-512` | hash_512 | 23933 | 1696 KiB | 1776 KiB |
| `ZC-EDMC-1536-512` | hash_1024 | 23933 | 1700 KiB | 1764 KiB |
| `ZC-EDMC-1536-512` | hash_4096 | 23933 | 1700 KiB | 1764 KiB |
| `ZC-EDMC-1536-512` | hash_8192 | 23933 | 1684 KiB | 1796 KiB |
| `ZC-EDMC-1536-512` | hash_16384 | 23933 | 1704 KiB | 1768 KiB |
| `ZC-EDMC-1536-512` | hash_65536 | 23933 | 1764 KiB | 1844 KiB |
| `ZC-EDMC-1536-768` | hash_32 | 23933 | 1696 KiB | 1772 KiB |
| `ZC-EDMC-1536-768` | hash_128 | 23933 | 1676 KiB | 1740 KiB |
| `ZC-EDMC-1536-768` | hash_512 | 23933 | 1688 KiB | 1752 KiB |
| `ZC-EDMC-1536-768` | hash_1024 | 23933 | 1692 KiB | 1780 KiB |
| `ZC-EDMC-1536-768` | hash_4096 | 23933 | 1704 KiB | 1768 KiB |
| `ZC-EDMC-1536-768` | hash_8192 | 23933 | 1700 KiB | 1796 KiB |
| `ZC-EDMC-1536-768` | hash_16384 | 23933 | 1708 KiB | 1772 KiB |
| `ZC-EDMC-1536-768` | hash_65536 | 23933 | 1752 KiB | 1852 KiB |
| `ZC-EDMC-1536-1024` | hash_32 | 23933 | 1672 KiB | 1772 KiB |
| `ZC-EDMC-1536-1024` | hash_128 | 23933 | 1684 KiB | 1780 KiB |
| `ZC-EDMC-1536-1024` | hash_512 | 23933 | 1700 KiB | 1764 KiB |
| `ZC-EDMC-1536-1024` | hash_1024 | 23933 | 1692 KiB | 1756 KiB |
| `ZC-EDMC-1536-1024` | hash_4096 | 23933 | 1672 KiB | 1796 KiB |
| `ZC-EDMC-1536-1024` | hash_8192 | 23933 | 1700 KiB | 1796 KiB |
| `ZC-EDMC-1536-1024` | hash_16384 | 23933 | 1680 KiB | 1804 KiB |
| `ZC-EDMC-1536-1024` | hash_65536 | 23933 | 1748 KiB | 1812 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `ZC-EDMC-1280-512` | KAT log (sha256 `0a3f497a73b00520…`) | `kat/hash-32/ZC-EDMC-1280-512.log` |
| `ZC-EDMC-1280-512` | timing hash_1024 | `records/hash-32/ZC-EDMC-1280-512__hash_1024.json` |
| `ZC-EDMC-1280-512` | timing hash_128 | `records/hash-32/ZC-EDMC-1280-512__hash_128.json` |
| `ZC-EDMC-1280-512` | timing hash_16384 | `records/hash-32/ZC-EDMC-1280-512__hash_16384.json` |
| `ZC-EDMC-1280-512` | timing hash_32 | `records/hash-32/ZC-EDMC-1280-512__hash_32.json` |
| `ZC-EDMC-1280-512` | timing hash_4096 | `records/hash-32/ZC-EDMC-1280-512__hash_4096.json` |
| `ZC-EDMC-1280-512` | timing hash_512 | `records/hash-32/ZC-EDMC-1280-512__hash_512.json` |
| `ZC-EDMC-1280-512` | timing hash_65536 | `records/hash-32/ZC-EDMC-1280-512__hash_65536.json` |
| `ZC-EDMC-1280-512` | timing hash_8192 | `records/hash-32/ZC-EDMC-1280-512__hash_8192.json` |
| `ZC-EDMC-1280-768` | KAT log (sha256 `05b6fc1f9d971f9c…`) | `kat/hash-32/ZC-EDMC-1280-768.log` |
| `ZC-EDMC-1280-768` | timing hash_1024 | `records/hash-32/ZC-EDMC-1280-768__hash_1024.json` |
| `ZC-EDMC-1280-768` | timing hash_128 | `records/hash-32/ZC-EDMC-1280-768__hash_128.json` |
| `ZC-EDMC-1280-768` | timing hash_16384 | `records/hash-32/ZC-EDMC-1280-768__hash_16384.json` |
| `ZC-EDMC-1280-768` | timing hash_32 | `records/hash-32/ZC-EDMC-1280-768__hash_32.json` |
| `ZC-EDMC-1280-768` | timing hash_4096 | `records/hash-32/ZC-EDMC-1280-768__hash_4096.json` |
| `ZC-EDMC-1280-768` | timing hash_512 | `records/hash-32/ZC-EDMC-1280-768__hash_512.json` |
| `ZC-EDMC-1280-768` | timing hash_65536 | `records/hash-32/ZC-EDMC-1280-768__hash_65536.json` |
| `ZC-EDMC-1280-768` | timing hash_8192 | `records/hash-32/ZC-EDMC-1280-768__hash_8192.json` |
| `ZC-EDMC-1280-1024` | KAT log (sha256 `05a1719c9a143cef…`) | `kat/hash-32/ZC-EDMC-1280-1024.log` |
| `ZC-EDMC-1280-1024` | timing hash_1024 | `records/hash-32/ZC-EDMC-1280-1024__hash_1024.json` |
| `ZC-EDMC-1280-1024` | timing hash_128 | `records/hash-32/ZC-EDMC-1280-1024__hash_128.json` |
| `ZC-EDMC-1280-1024` | timing hash_16384 | `records/hash-32/ZC-EDMC-1280-1024__hash_16384.json` |
| `ZC-EDMC-1280-1024` | timing hash_32 | `records/hash-32/ZC-EDMC-1280-1024__hash_32.json` |
| `ZC-EDMC-1280-1024` | timing hash_4096 | `records/hash-32/ZC-EDMC-1280-1024__hash_4096.json` |
| `ZC-EDMC-1280-1024` | timing hash_512 | `records/hash-32/ZC-EDMC-1280-1024__hash_512.json` |
| `ZC-EDMC-1280-1024` | timing hash_65536 | `records/hash-32/ZC-EDMC-1280-1024__hash_65536.json` |
| `ZC-EDMC-1280-1024` | timing hash_8192 | `records/hash-32/ZC-EDMC-1280-1024__hash_8192.json` |
| `ZC-EDMC-1536-512` | KAT log (sha256 `442b59df234cb59e…`) | `kat/hash-32/ZC-EDMC-1536-512.log` |
| `ZC-EDMC-1536-512` | timing hash_1024 | `records/hash-32/ZC-EDMC-1536-512__hash_1024.json` |
| `ZC-EDMC-1536-512` | timing hash_128 | `records/hash-32/ZC-EDMC-1536-512__hash_128.json` |
| `ZC-EDMC-1536-512` | timing hash_16384 | `records/hash-32/ZC-EDMC-1536-512__hash_16384.json` |
| `ZC-EDMC-1536-512` | timing hash_32 | `records/hash-32/ZC-EDMC-1536-512__hash_32.json` |
| `ZC-EDMC-1536-512` | timing hash_4096 | `records/hash-32/ZC-EDMC-1536-512__hash_4096.json` |
| `ZC-EDMC-1536-512` | timing hash_512 | `records/hash-32/ZC-EDMC-1536-512__hash_512.json` |
| `ZC-EDMC-1536-512` | timing hash_65536 | `records/hash-32/ZC-EDMC-1536-512__hash_65536.json` |
| `ZC-EDMC-1536-512` | timing hash_8192 | `records/hash-32/ZC-EDMC-1536-512__hash_8192.json` |
| `ZC-EDMC-1536-768` | KAT log (sha256 `cf71e26317c8c8d6…`) | `kat/hash-32/ZC-EDMC-1536-768.log` |
| `ZC-EDMC-1536-768` | timing hash_1024 | `records/hash-32/ZC-EDMC-1536-768__hash_1024.json` |
| `ZC-EDMC-1536-768` | timing hash_128 | `records/hash-32/ZC-EDMC-1536-768__hash_128.json` |
| `ZC-EDMC-1536-768` | timing hash_16384 | `records/hash-32/ZC-EDMC-1536-768__hash_16384.json` |
| `ZC-EDMC-1536-768` | timing hash_32 | `records/hash-32/ZC-EDMC-1536-768__hash_32.json` |
| `ZC-EDMC-1536-768` | timing hash_4096 | `records/hash-32/ZC-EDMC-1536-768__hash_4096.json` |
| `ZC-EDMC-1536-768` | timing hash_512 | `records/hash-32/ZC-EDMC-1536-768__hash_512.json` |
| `ZC-EDMC-1536-768` | timing hash_65536 | `records/hash-32/ZC-EDMC-1536-768__hash_65536.json` |
| `ZC-EDMC-1536-768` | timing hash_8192 | `records/hash-32/ZC-EDMC-1536-768__hash_8192.json` |
| `ZC-EDMC-1536-1024` | KAT log (sha256 `e8e2f9fca123f749…`) | `kat/hash-32/ZC-EDMC-1536-1024.log` |
| `ZC-EDMC-1536-1024` | timing hash_1024 | `records/hash-32/ZC-EDMC-1536-1024__hash_1024.json` |
| `ZC-EDMC-1536-1024` | timing hash_128 | `records/hash-32/ZC-EDMC-1536-1024__hash_128.json` |
| `ZC-EDMC-1536-1024` | timing hash_16384 | `records/hash-32/ZC-EDMC-1536-1024__hash_16384.json` |
| `ZC-EDMC-1536-1024` | timing hash_32 | `records/hash-32/ZC-EDMC-1536-1024__hash_32.json` |
| `ZC-EDMC-1536-1024` | timing hash_4096 | `records/hash-32/ZC-EDMC-1536-1024__hash_4096.json` |
| `ZC-EDMC-1536-1024` | timing hash_512 | `records/hash-32/ZC-EDMC-1536-1024__hash_512.json` |
| `ZC-EDMC-1536-1024` | timing hash_65536 | `records/hash-32/ZC-EDMC-1536-1024__hash_65536.json` |
| `ZC-EDMC-1536-1024` | timing hash_8192 | `records/hash-32/ZC-EDMC-1536-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

