<!-- synchronized from harness: hash-31/perf_x86_1.md -->
# hash-31 The ZC-DMC Hash Function — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-31` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101534457934204928.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-31.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: The ZC-DMC Hash Function
- Implementation versions measured: optimized (AVX2), reference
- Parameter sets: `ZC-DMC-1280-512`, `ZC-DMC-1280-512-avx2`, `ZC-DMC-1280-768`, `ZC-DMC-1280-768-avx2`, `ZC-DMC-1280-1024`, `ZC-DMC-1280-1024-avx2`, `ZC-DMC-1536-512`, `ZC-DMC-1536-512-avx2`, `ZC-DMC-1536-768`, `ZC-DMC-1536-768-avx2`, `ZC-DMC-1536-1024`, `ZC-DMC-1536-1024-avx2`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-31/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `ZC-DMC-1280-512` | guide | PASS |
| `ZC-DMC-1280-512-avx2` | guide-performance | PASS |
| `ZC-DMC-1280-768` | guide | PASS |
| `ZC-DMC-1280-768-avx2` | guide-performance | PASS |
| `ZC-DMC-1280-1024` | guide | PASS |
| `ZC-DMC-1280-1024-avx2` | guide-performance | PASS |
| `ZC-DMC-1536-512` | guide | PASS |
| `ZC-DMC-1536-512-avx2` | guide-performance | PASS |
| `ZC-DMC-1536-768` | guide | PASS |
| `ZC-DMC-1536-768-avx2` | guide-performance | PASS |
| `ZC-DMC-1536-1024` | guide | PASS |
| `ZC-DMC-1536-1024-avx2` | guide-performance | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `ZC-DMC-1280-512` | 32 B | 5167 | 161.5 | 2.47 µs | 13.0 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512` | 128 B | 5728 | 44.7 | 2.74 µs | 46.7 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512` | 512 B | 7893 | 15.4 | 3.77 µs | 135.7 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512` | 1024 B | 11.4 k | 11.2 | 5.46 µs | 187.5 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512` | 4096 B | 32.4 k | 7.9 | 15.5 µs | 264.9 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512` | 8192 B | 60.2 k | 7.4 | 28.8 µs | 284.8 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512` | 16384 B | 115.0 k | 7.0 | 54.9 µs | 298.4 | 81825 (5 × 16365) |
| `ZC-DMC-1280-512` | 65536 B | 442.6 k | 6.8 | 211 µs | 309.9 | 21685 (5 × 4337) |
| `ZC-DMC-1280-512-avx2` | 32 B | 3779 | 118.1 | 1.81 µs | 17.7 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512-avx2` | 128 B | 4161 | 32.5 | 1.99 µs | 64.3 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512-avx2` | 512 B | 5636 | 11.0 | 2.69 µs | 190.0 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512-avx2` | 1024 B | 8347 | 8.2 | 3.99 µs | 256.7 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512-avx2` | 4096 B | 23.6 k | 5.8 | 11.3 µs | 363.7 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512-avx2` | 8192 B | 44.5 k | 5.4 | 21.3 µs | 385.4 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512-avx2` | 16384 B | 84.5 k | 5.2 | 40.4 µs | 405.7 | 100000 (5 × 20000) |
| `ZC-DMC-1280-512-avx2` | 65536 B | 326.5 k | 5.0 | 156 µs | 420.1 | 30940 (5 × 6188) |
| `ZC-DMC-1280-768` | 32 B | 7239 | 226.2 | 3.46 µs | 9.2 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768` | 128 B | 8496 | 66.4 | 4.06 µs | 31.5 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768` | 512 B | 12.6 k | 24.7 | 6.03 µs | 84.9 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768` | 1024 B | 17.9 k | 17.4 | 8.53 µs | 120.0 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768` | 4096 B | 50.5 k | 12.3 | 24.1 µs | 169.8 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768` | 8192 B | 93.3 k | 11.4 | 44.6 µs | 183.8 | 98685 (5 × 19737) |
| `ZC-DMC-1280-768` | 16384 B | 178.5 k | 10.9 | 85.3 µs | 192.2 | 23200 (5 × 4640) |
| `ZC-DMC-1280-768` | 65536 B | 696.1 k | 10.6 | 334 µs | 196.4 | 15165 (5 × 3033) |
| `ZC-DMC-1280-768-avx2` | 32 B | 5141 | 160.7 | 2.46 µs | 13.0 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768-avx2` | 128 B | 6160 | 48.1 | 2.94 µs | 43.5 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768-avx2` | 512 B | 9281 | 18.1 | 4.44 µs | 115.4 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768-avx2` | 1024 B | 13.1 k | 12.8 | 6.27 µs | 163.3 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768-avx2` | 4096 B | 37.1 k | 9.1 | 17.7 µs | 231.2 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768-avx2` | 8192 B | 68.9 k | 8.4 | 32.9 µs | 248.8 | 100000 (5 × 20000) |
| `ZC-DMC-1280-768-avx2` | 16384 B | 132.3 k | 8.1 | 63.2 µs | 259.2 | 71540 (5 × 14308) |
| `ZC-DMC-1280-768-avx2` | 65536 B | 515.5 k | 7.9 | 246 µs | 266.1 | 19805 (5 × 3961) |
| `ZC-DMC-1280-1024` | 32 B | 9852 | 307.9 | 4.71 µs | 6.8 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024` | 128 B | 12.2 k | 95.2 | 5.83 µs | 22.0 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024` | 512 B | 21.7 k | 42.3 | 10.4 µs | 49.5 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024` | 1024 B | 34.0 k | 33.2 | 16.2 µs | 63.1 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024` | 4096 B | 109.5 k | 26.7 | 52.3 µs | 78.3 | 86020 (5 × 17204) |
| `ZC-DMC-1280-1024` | 8192 B | 208.2 k | 25.4 | 99.5 µs | 82.3 | 46335 (5 × 9267) |
| `ZC-DMC-1280-1024` | 16384 B | 408.7 k | 24.9 | 195 µs | 83.9 | 24350 (5 × 4870) |
| `ZC-DMC-1280-1024` | 65536 B | 1.62 M | 24.8 | 776 µs | 84.4 | 6595 (5 × 1319) |
| `ZC-DMC-1280-1024-avx2` | 32 B | 7150 | 223.4 | 3.42 µs | 9.4 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024-avx2` | 128 B | 9043 | 70.6 | 4.32 µs | 29.6 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024-avx2` | 512 B | 16.1 k | 31.4 | 7.68 µs | 66.7 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024-avx2` | 1024 B | 24.9 k | 24.4 | 11.9 µs | 86.0 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024-avx2` | 4096 B | 80.8 k | 19.7 | 38.6 µs | 106.1 | 100000 (5 × 20000) |
| `ZC-DMC-1280-1024-avx2` | 8192 B | 155.1 k | 18.9 | 74.1 µs | 110.6 | 62005 (5 × 12401) |
| `ZC-DMC-1280-1024-avx2` | 16384 B | 303.5 k | 18.5 | 145 µs | 113.0 | 32825 (5 × 6565) |
| `ZC-DMC-1280-1024-avx2` | 65536 B | 1.19 M | 18.2 | 570 µs | 115.0 | 8640 (5 × 1728) |
| `ZC-DMC-1536-512` | 32 B | 9099 | 284.4 | 4.35 µs | 7.4 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512` | 128 B | 10.4 k | 80.9 | 4.95 µs | 25.9 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512` | 512 B | 13.4 k | 26.1 | 6.39 µs | 80.1 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512` | 1024 B | 17.4 k | 17.0 | 8.33 µs | 122.9 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512` | 4096 B | 45.4 k | 11.1 | 21.7 µs | 188.7 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512` | 8192 B | 81.7 k | 10.0 | 39 µs | 210.0 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512` | 16384 B | 153.4 k | 9.4 | 73.3 µs | 223.5 | 61905 (5 × 12381) |
| `ZC-DMC-1536-512` | 65536 B | 593.3 k | 9.1 | 283 µs | 231.2 | 17260 (5 × 3452) |
| `ZC-DMC-1536-512-avx2` | 32 B | 12.3 k | 384.6 | 5.88 µs | 5.4 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512-avx2` | 128 B | 13.9 k | 108.7 | 6.65 µs | 19.3 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512-avx2` | 512 B | 18.0 k | 35.2 | 8.61 µs | 59.5 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512-avx2` | 1024 B | 23.6 k | 23.0 | 11.3 µs | 90.9 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512-avx2` | 4096 B | 63.7 k | 15.6 | 30.4 µs | 134.6 | 100000 (5 × 20000) |
| `ZC-DMC-1536-512-avx2` | 8192 B | 112.2 k | 13.7 | 53.6 µs | 152.9 | 83335 (5 × 16667) |
| `ZC-DMC-1536-512-avx2` | 16384 B | 210.3 k | 12.8 | 101 µs | 163.0 | 37450 (5 × 7490) |
| `ZC-DMC-1536-512-avx2` | 65536 B | 825.0 k | 12.6 | 394 µs | 166.3 | 12290 (5 × 2458) |
| `ZC-DMC-1536-768` | 32 B | 12.9 k | 404.4 | 6.18 µs | 5.2 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768` | 128 B | 13.9 k | 108.8 | 6.65 µs | 19.2 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768` | 512 B | 18.0 k | 35.1 | 8.59 µs | 59.6 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768` | 1024 B | 24.4 k | 23.9 | 11.7 µs | 87.7 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768` | 4096 B | 62.0 k | 15.1 | 29.6 µs | 138.2 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768` | 8192 B | 112.2 k | 13.7 | 53.6 µs | 152.8 | 82290 (5 × 16458) |
| `ZC-DMC-1536-768` | 16384 B | 211.0 k | 12.9 | 101 µs | 162.6 | 46665 (5 × 9333) |
| `ZC-DMC-1536-768` | 65536 B | 808.9 k | 12.3 | 386 µs | 169.6 | 12565 (5 × 2513) |
| `ZC-DMC-1536-768-avx2` | 32 B | 17.7 k | 554.6 | 8.48 µs | 3.8 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768-avx2` | 128 B | 19.2 k | 149.8 | 9.16 µs | 14.0 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768-avx2` | 512 B | 25.0 k | 48.9 | 12 µs | 42.8 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768-avx2` | 1024 B | 33.8 k | 33.0 | 16.2 µs | 63.3 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768-avx2` | 4096 B | 86.2 k | 21.1 | 41.2 µs | 99.4 | 100000 (5 × 20000) |
| `ZC-DMC-1536-768-avx2` | 8192 B | 157.2 k | 19.2 | 75.1 µs | 109.1 | 62715 (5 × 12543) |
| `ZC-DMC-1536-768-avx2` | 16384 B | 290.2 k | 17.7 | 139 µs | 117.9 | 34290 (5 × 6858) |
| `ZC-DMC-1536-768-avx2` | 65536 B | 1.15 M | 17.5 | 547 µs | 119.8 | 5060 (5 × 1012) |
| `ZC-DMC-1536-1024` | 32 B | 16.7 k | 521.9 | 7.98 µs | 4.0 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024` | 128 B | 19.0 k | 148.4 | 9.08 µs | 14.1 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024` | 512 B | 26.6 k | 51.9 | 12.7 µs | 40.3 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024` | 1024 B | 36.1 k | 35.3 | 17.3 µs | 59.3 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024` | 4096 B | 94.9 k | 23.2 | 45.3 µs | 90.4 | 95595 (5 × 19119) |
| `ZC-DMC-1536-1024` | 8192 B | 172.6 k | 21.1 | 82.5 µs | 99.3 | 51535 (5 × 10307) |
| `ZC-DMC-1536-1024` | 16384 B | 327.7 k | 20.0 | 157 µs | 104.6 | 30525 (5 × 6105) |
| `ZC-DMC-1536-1024` | 65536 B | 1.26 M | 19.3 | 604 µs | 108.5 | 8155 (5 × 1631) |
| `ZC-DMC-1536-1024-avx2` | 32 B | 23.2 k | 726.4 | 11.1 µs | 2.9 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024-avx2` | 128 B | 26.5 k | 206.9 | 12.7 µs | 10.1 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024-avx2` | 512 B | 36.5 k | 71.2 | 17.4 µs | 29.4 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024-avx2` | 1024 B | 50.4 k | 49.2 | 24.1 µs | 42.5 | 100000 (5 × 20000) |
| `ZC-DMC-1536-1024-avx2` | 4096 B | 131.8 k | 32.2 | 63 µs | 65.0 | 72285 (5 × 14457) |
| `ZC-DMC-1536-1024-avx2` | 8192 B | 236.9 k | 28.9 | 113 µs | 72.4 | 41910 (5 × 8382) |
| `ZC-DMC-1536-1024-avx2` | 16384 B | 451.5 k | 27.6 | 216 µs | 76.0 | 22540 (5 × 4508) |
| `ZC-DMC-1536-1024-avx2` | 65536 B | 1.76 M | 26.8 | 839 µs | 78.1 | 6035 (5 × 1207) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `ZC-DMC-1280-512` | hash_32 | 15269 | 1684 KiB | 1780 KiB |
| `ZC-DMC-1280-512` | hash_128 | 15269 | 1692 KiB | 1756 KiB |
| `ZC-DMC-1280-512` | hash_512 | 15269 | 1688 KiB | 1752 KiB |
| `ZC-DMC-1280-512` | hash_1024 | 15269 | 1688 KiB | 1784 KiB |
| `ZC-DMC-1280-512` | hash_4096 | 15269 | 1680 KiB | 1788 KiB |
| `ZC-DMC-1280-512` | hash_8192 | 15269 | 1700 KiB | 1780 KiB |
| `ZC-DMC-1280-512` | hash_16384 | 15269 | 1688 KiB | 1776 KiB |
| `ZC-DMC-1280-512` | hash_65536 | 15269 | 1740 KiB | 1832 KiB |
| `ZC-DMC-1280-512-avx2` | hash_32 | 18401 | 1696 KiB | 1776 KiB |
| `ZC-DMC-1280-512-avx2` | hash_128 | 18401 | 1680 KiB | 1744 KiB |
| `ZC-DMC-1280-512-avx2` | hash_512 | 18401 | 1696 KiB | 1784 KiB |
| `ZC-DMC-1280-512-avx2` | hash_1024 | 18401 | 1648 KiB | 1776 KiB |
| `ZC-DMC-1280-512-avx2` | hash_4096 | 18401 | 1692 KiB | 1756 KiB |
| `ZC-DMC-1280-512-avx2` | hash_8192 | 18401 | 1692 KiB | 1788 KiB |
| `ZC-DMC-1280-512-avx2` | hash_16384 | 18401 | 1668 KiB | 1796 KiB |
| `ZC-DMC-1280-512-avx2` | hash_65536 | 18401 | 1752 KiB | 1816 KiB |
| `ZC-DMC-1280-768` | hash_32 | 15269 | 1660 KiB | 1784 KiB |
| `ZC-DMC-1280-768` | hash_128 | 15269 | 1592 KiB | 1720 KiB |
| `ZC-DMC-1280-768` | hash_512 | 15269 | 1676 KiB | 1776 KiB |
| `ZC-DMC-1280-768` | hash_1024 | 15269 | 1684 KiB | 1784 KiB |
| `ZC-DMC-1280-768` | hash_4096 | 15269 | 1696 KiB | 1784 KiB |
| `ZC-DMC-1280-768` | hash_8192 | 15269 | 1704 KiB | 1780 KiB |
| `ZC-DMC-1280-768` | hash_16384 | 15269 | 1708 KiB | 1792 KiB |
| `ZC-DMC-1280-768` | hash_65536 | 15269 | 1744 KiB | 1844 KiB |
| `ZC-DMC-1280-768-avx2` | hash_32 | 18401 | 1688 KiB | 1784 KiB |
| `ZC-DMC-1280-768-avx2` | hash_128 | 18401 | 1688 KiB | 1776 KiB |
| `ZC-DMC-1280-768-avx2` | hash_512 | 18401 | 1676 KiB | 1764 KiB |
| `ZC-DMC-1280-768-avx2` | hash_1024 | 18401 | 1684 KiB | 1760 KiB |
| `ZC-DMC-1280-768-avx2` | hash_4096 | 18401 | 1700 KiB | 1764 KiB |
| `ZC-DMC-1280-768-avx2` | hash_8192 | 18401 | 1704 KiB | 1796 KiB |
| `ZC-DMC-1280-768-avx2` | hash_16384 | 18401 | 1692 KiB | 1796 KiB |
| `ZC-DMC-1280-768-avx2` | hash_65536 | 18401 | 1740 KiB | 1828 KiB |
| `ZC-DMC-1280-1024` | hash_32 | 15269 | 1684 KiB | 1772 KiB |
| `ZC-DMC-1280-1024` | hash_128 | 15269 | 1660 KiB | 1784 KiB |
| `ZC-DMC-1280-1024` | hash_512 | 15269 | 1688 KiB | 1760 KiB |
| `ZC-DMC-1280-1024` | hash_1024 | 15269 | 1684 KiB | 1748 KiB |
| `ZC-DMC-1280-1024` | hash_4096 | 15269 | 1664 KiB | 1788 KiB |
| `ZC-DMC-1280-1024` | hash_8192 | 15269 | 1684 KiB | 1748 KiB |
| `ZC-DMC-1280-1024` | hash_16384 | 15269 | 1692 KiB | 1788 KiB |
| `ZC-DMC-1280-1024` | hash_65536 | 15269 | 1752 KiB | 1816 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_32 | 18401 | 1700 KiB | 1776 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_128 | 18401 | 1672 KiB | 1736 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_512 | 18401 | 1668 KiB | 1788 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_1024 | 18401 | 1696 KiB | 1788 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_4096 | 18401 | 1700 KiB | 1792 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_8192 | 18401 | 1660 KiB | 1788 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_16384 | 18401 | 1716 KiB | 1792 KiB |
| `ZC-DMC-1280-1024-avx2` | hash_65536 | 18401 | 1732 KiB | 1844 KiB |
| `ZC-DMC-1536-512` | hash_32 | 23837 | 1684 KiB | 1792 KiB |
| `ZC-DMC-1536-512` | hash_128 | 23837 | 1700 KiB | 1784 KiB |
| `ZC-DMC-1536-512` | hash_512 | 23837 | 1684 KiB | 1784 KiB |
| `ZC-DMC-1536-512` | hash_1024 | 23837 | 1676 KiB | 1788 KiB |
| `ZC-DMC-1536-512` | hash_4096 | 23837 | 1684 KiB | 1748 KiB |
| `ZC-DMC-1536-512` | hash_8192 | 23837 | 1692 KiB | 1800 KiB |
| `ZC-DMC-1536-512` | hash_16384 | 23837 | 1700 KiB | 1804 KiB |
| `ZC-DMC-1536-512` | hash_65536 | 23837 | 1736 KiB | 1852 KiB |
| `ZC-DMC-1536-512-avx2` | hash_32 | 15849 | 1692 KiB | 1756 KiB |
| `ZC-DMC-1536-512-avx2` | hash_128 | 15849 | 1692 KiB | 1756 KiB |
| `ZC-DMC-1536-512-avx2` | hash_512 | 15849 | 1696 KiB | 1780 KiB |
| `ZC-DMC-1536-512-avx2` | hash_1024 | 15849 | 1684 KiB | 1748 KiB |
| `ZC-DMC-1536-512-avx2` | hash_4096 | 15849 | 1700 KiB | 1764 KiB |
| `ZC-DMC-1536-512-avx2` | hash_8192 | 15849 | 1684 KiB | 1748 KiB |
| `ZC-DMC-1536-512-avx2` | hash_16384 | 15849 | 1696 KiB | 1760 KiB |
| `ZC-DMC-1536-512-avx2` | hash_65536 | 15849 | 1760 KiB | 1848 KiB |
| `ZC-DMC-1536-768` | hash_32 | 23837 | 1704 KiB | 1788 KiB |
| `ZC-DMC-1536-768` | hash_128 | 23837 | 1696 KiB | 1760 KiB |
| `ZC-DMC-1536-768` | hash_512 | 23837 | 1704 KiB | 1768 KiB |
| `ZC-DMC-1536-768` | hash_1024 | 23837 | 1700 KiB | 1768 KiB |
| `ZC-DMC-1536-768` | hash_4096 | 23837 | 1700 KiB | 1792 KiB |
| `ZC-DMC-1536-768` | hash_8192 | 23837 | 1692 KiB | 1788 KiB |
| `ZC-DMC-1536-768` | hash_16384 | 23837 | 1720 KiB | 1804 KiB |
| `ZC-DMC-1536-768` | hash_65536 | 23837 | 1760 KiB | 1856 KiB |
| `ZC-DMC-1536-768-avx2` | hash_32 | 15849 | 1688 KiB | 1784 KiB |
| `ZC-DMC-1536-768-avx2` | hash_128 | 15849 | 1676 KiB | 1780 KiB |
| `ZC-DMC-1536-768-avx2` | hash_512 | 15849 | 1696 KiB | 1780 KiB |
| `ZC-DMC-1536-768-avx2` | hash_1024 | 15849 | 1692 KiB | 1756 KiB |
| `ZC-DMC-1536-768-avx2` | hash_4096 | 15849 | 1696 KiB | 1780 KiB |
| `ZC-DMC-1536-768-avx2` | hash_8192 | 15849 | 1700 KiB | 1764 KiB |
| `ZC-DMC-1536-768-avx2` | hash_16384 | 15849 | 1700 KiB | 1764 KiB |
| `ZC-DMC-1536-768-avx2` | hash_65536 | 15849 | 1744 KiB | 1808 KiB |
| `ZC-DMC-1536-1024` | hash_32 | 23837 | 1684 KiB | 1748 KiB |
| `ZC-DMC-1536-1024` | hash_128 | 23837 | 1704 KiB | 1788 KiB |
| `ZC-DMC-1536-1024` | hash_512 | 23837 | 1676 KiB | 1780 KiB |
| `ZC-DMC-1536-1024` | hash_1024 | 23837 | 1696 KiB | 1784 KiB |
| `ZC-DMC-1536-1024` | hash_4096 | 23837 | 1656 KiB | 1784 KiB |
| `ZC-DMC-1536-1024` | hash_8192 | 23837 | 1708 KiB | 1772 KiB |
| `ZC-DMC-1536-1024` | hash_16384 | 23837 | 1716 KiB | 1804 KiB |
| `ZC-DMC-1536-1024` | hash_65536 | 23837 | 1760 KiB | 1844 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_32 | 15849 | 1680 KiB | 1780 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_128 | 15849 | 1684 KiB | 1748 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_512 | 15849 | 1696 KiB | 1784 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_1024 | 15849 | 1688 KiB | 1760 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_4096 | 15849 | 1692 KiB | 1788 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_8192 | 15849 | 1700 KiB | 1780 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_16384 | 15849 | 1712 KiB | 1788 KiB |
| `ZC-DMC-1536-1024-avx2` | hash_65536 | 15849 | 1760 KiB | 1824 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `ZC-DMC-1280-512` | KAT log (sha256 `d2a801ee1ffc203a…`) | `kat/hash-31/ZC-DMC-1280-512.log` |
| `ZC-DMC-1280-512` | timing hash_1024 | `records/hash-31/ZC-DMC-1280-512__hash_1024.json` |
| `ZC-DMC-1280-512` | timing hash_128 | `records/hash-31/ZC-DMC-1280-512__hash_128.json` |
| `ZC-DMC-1280-512` | timing hash_16384 | `records/hash-31/ZC-DMC-1280-512__hash_16384.json` |
| `ZC-DMC-1280-512` | timing hash_32 | `records/hash-31/ZC-DMC-1280-512__hash_32.json` |
| `ZC-DMC-1280-512` | timing hash_4096 | `records/hash-31/ZC-DMC-1280-512__hash_4096.json` |
| `ZC-DMC-1280-512` | timing hash_512 | `records/hash-31/ZC-DMC-1280-512__hash_512.json` |
| `ZC-DMC-1280-512` | timing hash_65536 | `records/hash-31/ZC-DMC-1280-512__hash_65536.json` |
| `ZC-DMC-1280-512` | timing hash_8192 | `records/hash-31/ZC-DMC-1280-512__hash_8192.json` |
| `ZC-DMC-1280-512-avx2` | KAT log (sha256 `b8d145282936c95b…`) | `kat/hash-31/ZC-DMC-1280-512-avx2.log` |
| `ZC-DMC-1280-512-avx2` | timing hash_1024 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_1024.json` |
| `ZC-DMC-1280-512-avx2` | timing hash_128 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_128.json` |
| `ZC-DMC-1280-512-avx2` | timing hash_16384 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_16384.json` |
| `ZC-DMC-1280-512-avx2` | timing hash_32 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_32.json` |
| `ZC-DMC-1280-512-avx2` | timing hash_4096 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_4096.json` |
| `ZC-DMC-1280-512-avx2` | timing hash_512 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_512.json` |
| `ZC-DMC-1280-512-avx2` | timing hash_65536 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_65536.json` |
| `ZC-DMC-1280-512-avx2` | timing hash_8192 | `records/hash-31/ZC-DMC-1280-512-avx2__hash_8192.json` |
| `ZC-DMC-1280-768` | KAT log (sha256 `922719c2f3e503d1…`) | `kat/hash-31/ZC-DMC-1280-768.log` |
| `ZC-DMC-1280-768` | timing hash_1024 | `records/hash-31/ZC-DMC-1280-768__hash_1024.json` |
| `ZC-DMC-1280-768` | timing hash_128 | `records/hash-31/ZC-DMC-1280-768__hash_128.json` |
| `ZC-DMC-1280-768` | timing hash_16384 | `records/hash-31/ZC-DMC-1280-768__hash_16384.json` |
| `ZC-DMC-1280-768` | timing hash_32 | `records/hash-31/ZC-DMC-1280-768__hash_32.json` |
| `ZC-DMC-1280-768` | timing hash_4096 | `records/hash-31/ZC-DMC-1280-768__hash_4096.json` |
| `ZC-DMC-1280-768` | timing hash_512 | `records/hash-31/ZC-DMC-1280-768__hash_512.json` |
| `ZC-DMC-1280-768` | timing hash_65536 | `records/hash-31/ZC-DMC-1280-768__hash_65536.json` |
| `ZC-DMC-1280-768` | timing hash_8192 | `records/hash-31/ZC-DMC-1280-768__hash_8192.json` |
| `ZC-DMC-1280-768-avx2` | KAT log (sha256 `5f4872672fc53ae8…`) | `kat/hash-31/ZC-DMC-1280-768-avx2.log` |
| `ZC-DMC-1280-768-avx2` | timing hash_1024 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_1024.json` |
| `ZC-DMC-1280-768-avx2` | timing hash_128 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_128.json` |
| `ZC-DMC-1280-768-avx2` | timing hash_16384 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_16384.json` |
| `ZC-DMC-1280-768-avx2` | timing hash_32 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_32.json` |
| `ZC-DMC-1280-768-avx2` | timing hash_4096 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_4096.json` |
| `ZC-DMC-1280-768-avx2` | timing hash_512 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_512.json` |
| `ZC-DMC-1280-768-avx2` | timing hash_65536 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_65536.json` |
| `ZC-DMC-1280-768-avx2` | timing hash_8192 | `records/hash-31/ZC-DMC-1280-768-avx2__hash_8192.json` |
| `ZC-DMC-1280-1024` | KAT log (sha256 `16ed045c1a595223…`) | `kat/hash-31/ZC-DMC-1280-1024.log` |
| `ZC-DMC-1280-1024` | timing hash_1024 | `records/hash-31/ZC-DMC-1280-1024__hash_1024.json` |
| `ZC-DMC-1280-1024` | timing hash_128 | `records/hash-31/ZC-DMC-1280-1024__hash_128.json` |
| `ZC-DMC-1280-1024` | timing hash_16384 | `records/hash-31/ZC-DMC-1280-1024__hash_16384.json` |
| `ZC-DMC-1280-1024` | timing hash_32 | `records/hash-31/ZC-DMC-1280-1024__hash_32.json` |
| `ZC-DMC-1280-1024` | timing hash_4096 | `records/hash-31/ZC-DMC-1280-1024__hash_4096.json` |
| `ZC-DMC-1280-1024` | timing hash_512 | `records/hash-31/ZC-DMC-1280-1024__hash_512.json` |
| `ZC-DMC-1280-1024` | timing hash_65536 | `records/hash-31/ZC-DMC-1280-1024__hash_65536.json` |
| `ZC-DMC-1280-1024` | timing hash_8192 | `records/hash-31/ZC-DMC-1280-1024__hash_8192.json` |
| `ZC-DMC-1280-1024-avx2` | KAT log (sha256 `b6680339215abb31…`) | `kat/hash-31/ZC-DMC-1280-1024-avx2.log` |
| `ZC-DMC-1280-1024-avx2` | timing hash_1024 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_1024.json` |
| `ZC-DMC-1280-1024-avx2` | timing hash_128 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_128.json` |
| `ZC-DMC-1280-1024-avx2` | timing hash_16384 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_16384.json` |
| `ZC-DMC-1280-1024-avx2` | timing hash_32 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_32.json` |
| `ZC-DMC-1280-1024-avx2` | timing hash_4096 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_4096.json` |
| `ZC-DMC-1280-1024-avx2` | timing hash_512 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_512.json` |
| `ZC-DMC-1280-1024-avx2` | timing hash_65536 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_65536.json` |
| `ZC-DMC-1280-1024-avx2` | timing hash_8192 | `records/hash-31/ZC-DMC-1280-1024-avx2__hash_8192.json` |
| `ZC-DMC-1536-512` | KAT log (sha256 `9fc94c017c87b5f1…`) | `kat/hash-31/ZC-DMC-1536-512.log` |
| `ZC-DMC-1536-512` | timing hash_1024 | `records/hash-31/ZC-DMC-1536-512__hash_1024.json` |
| `ZC-DMC-1536-512` | timing hash_128 | `records/hash-31/ZC-DMC-1536-512__hash_128.json` |
| `ZC-DMC-1536-512` | timing hash_16384 | `records/hash-31/ZC-DMC-1536-512__hash_16384.json` |
| `ZC-DMC-1536-512` | timing hash_32 | `records/hash-31/ZC-DMC-1536-512__hash_32.json` |
| `ZC-DMC-1536-512` | timing hash_4096 | `records/hash-31/ZC-DMC-1536-512__hash_4096.json` |
| `ZC-DMC-1536-512` | timing hash_512 | `records/hash-31/ZC-DMC-1536-512__hash_512.json` |
| `ZC-DMC-1536-512` | timing hash_65536 | `records/hash-31/ZC-DMC-1536-512__hash_65536.json` |
| `ZC-DMC-1536-512` | timing hash_8192 | `records/hash-31/ZC-DMC-1536-512__hash_8192.json` |
| `ZC-DMC-1536-512-avx2` | KAT log (sha256 `0ca79fd32bef0530…`) | `kat/hash-31/ZC-DMC-1536-512-avx2.log` |
| `ZC-DMC-1536-512-avx2` | timing hash_1024 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_1024.json` |
| `ZC-DMC-1536-512-avx2` | timing hash_128 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_128.json` |
| `ZC-DMC-1536-512-avx2` | timing hash_16384 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_16384.json` |
| `ZC-DMC-1536-512-avx2` | timing hash_32 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_32.json` |
| `ZC-DMC-1536-512-avx2` | timing hash_4096 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_4096.json` |
| `ZC-DMC-1536-512-avx2` | timing hash_512 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_512.json` |
| `ZC-DMC-1536-512-avx2` | timing hash_65536 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_65536.json` |
| `ZC-DMC-1536-512-avx2` | timing hash_8192 | `records/hash-31/ZC-DMC-1536-512-avx2__hash_8192.json` |
| `ZC-DMC-1536-768` | KAT log (sha256 `db3e88fefab980a4…`) | `kat/hash-31/ZC-DMC-1536-768.log` |
| `ZC-DMC-1536-768` | timing hash_1024 | `records/hash-31/ZC-DMC-1536-768__hash_1024.json` |
| `ZC-DMC-1536-768` | timing hash_128 | `records/hash-31/ZC-DMC-1536-768__hash_128.json` |
| `ZC-DMC-1536-768` | timing hash_16384 | `records/hash-31/ZC-DMC-1536-768__hash_16384.json` |
| `ZC-DMC-1536-768` | timing hash_32 | `records/hash-31/ZC-DMC-1536-768__hash_32.json` |
| `ZC-DMC-1536-768` | timing hash_4096 | `records/hash-31/ZC-DMC-1536-768__hash_4096.json` |
| `ZC-DMC-1536-768` | timing hash_512 | `records/hash-31/ZC-DMC-1536-768__hash_512.json` |
| `ZC-DMC-1536-768` | timing hash_65536 | `records/hash-31/ZC-DMC-1536-768__hash_65536.json` |
| `ZC-DMC-1536-768` | timing hash_8192 | `records/hash-31/ZC-DMC-1536-768__hash_8192.json` |
| `ZC-DMC-1536-768-avx2` | KAT log (sha256 `94f19a7a92ad777f…`) | `kat/hash-31/ZC-DMC-1536-768-avx2.log` |
| `ZC-DMC-1536-768-avx2` | timing hash_1024 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_1024.json` |
| `ZC-DMC-1536-768-avx2` | timing hash_128 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_128.json` |
| `ZC-DMC-1536-768-avx2` | timing hash_16384 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_16384.json` |
| `ZC-DMC-1536-768-avx2` | timing hash_32 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_32.json` |
| `ZC-DMC-1536-768-avx2` | timing hash_4096 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_4096.json` |
| `ZC-DMC-1536-768-avx2` | timing hash_512 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_512.json` |
| `ZC-DMC-1536-768-avx2` | timing hash_65536 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_65536.json` |
| `ZC-DMC-1536-768-avx2` | timing hash_8192 | `records/hash-31/ZC-DMC-1536-768-avx2__hash_8192.json` |
| `ZC-DMC-1536-1024` | KAT log (sha256 `90edcda80547d921…`) | `kat/hash-31/ZC-DMC-1536-1024.log` |
| `ZC-DMC-1536-1024` | timing hash_1024 | `records/hash-31/ZC-DMC-1536-1024__hash_1024.json` |
| `ZC-DMC-1536-1024` | timing hash_128 | `records/hash-31/ZC-DMC-1536-1024__hash_128.json` |
| `ZC-DMC-1536-1024` | timing hash_16384 | `records/hash-31/ZC-DMC-1536-1024__hash_16384.json` |
| `ZC-DMC-1536-1024` | timing hash_32 | `records/hash-31/ZC-DMC-1536-1024__hash_32.json` |
| `ZC-DMC-1536-1024` | timing hash_4096 | `records/hash-31/ZC-DMC-1536-1024__hash_4096.json` |
| `ZC-DMC-1536-1024` | timing hash_512 | `records/hash-31/ZC-DMC-1536-1024__hash_512.json` |
| `ZC-DMC-1536-1024` | timing hash_65536 | `records/hash-31/ZC-DMC-1536-1024__hash_65536.json` |
| `ZC-DMC-1536-1024` | timing hash_8192 | `records/hash-31/ZC-DMC-1536-1024__hash_8192.json` |
| `ZC-DMC-1536-1024-avx2` | KAT log (sha256 `1e27635851e03c42…`) | `kat/hash-31/ZC-DMC-1536-1024-avx2.log` |
| `ZC-DMC-1536-1024-avx2` | timing hash_1024 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_1024.json` |
| `ZC-DMC-1536-1024-avx2` | timing hash_128 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_128.json` |
| `ZC-DMC-1536-1024-avx2` | timing hash_16384 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_16384.json` |
| `ZC-DMC-1536-1024-avx2` | timing hash_32 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_32.json` |
| `ZC-DMC-1536-1024-avx2` | timing hash_4096 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_4096.json` |
| `ZC-DMC-1536-1024-avx2` | timing hash_512 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_512.json` |
| `ZC-DMC-1536-1024-avx2` | timing hash_65536 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_65536.json` |
| `ZC-DMC-1536-1024-avx2` | timing hash_8192 | `records/hash-31/ZC-DMC-1536-1024-avx2__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

