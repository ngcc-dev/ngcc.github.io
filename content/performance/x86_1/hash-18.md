<!-- synchronized from harness: hash-18/perf_x86_1.md -->
# hash-18 Megascon Hash Function — performance on x86-64 (system x86_1)

[Performance x86_1](index.md) › `hash-18` · [method](method.md) · [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101537413073031168.html)

**Systems:** **x86_1** · [arm_1](../arm_1/hash-18.md)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Megascon Hash Function
- Implementation versions measured: reference
- Parameter sets: `MEGASCON-384`, `MEGASCON-384-XOF-256`, `MEGASCON-384-XOF-1024`, `MEGASCON-384-XOF-2048`, `MEGASCON-512`, `MEGASCON-512-XOF-256`, `MEGASCON-512-XOF-1024`, `MEGASCON-512-XOF-2048`, `MEGASCON-768`, `MEGASCON-1024`

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-18/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `MEGASCON-384` | guide | PASS |
| `MEGASCON-384-XOF-256` | guide | PASS |
| `MEGASCON-384-XOF-1024` | guide | PASS |
| `MEGASCON-384-XOF-2048` | guide | PASS |
| `MEGASCON-512` | guide | PASS |
| `MEGASCON-512-XOF-256` | guide | PASS |
| `MEGASCON-512-XOF-1024` | guide | PASS |
| `MEGASCON-512-XOF-2048` | guide | PASS |
| `MEGASCON-768` | guide | PASS |
| `MEGASCON-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `MEGASCON-384` | 32 B | 3021 | 94.4 | 1.5 µs | 21.4 | 100000 (5 × 20000) |
| `MEGASCON-384` | 128 B | 3019 | 23.6 | 1.5 µs | 85.6 | 100000 (5 × 20000) |
| `MEGASCON-384` | 512 B | 11.7 k | 22.8 | 5.8 µs | 88.3 | 100000 (5 × 20000) |
| `MEGASCON-384` | 1024 B | 20.3 k | 19.8 | 10.1 µs | 101.7 | 100000 (5 × 20000) |
| `MEGASCON-384` | 4096 B | 74.9 k | 18.3 | 37.2 µs | 110.0 | 100000 (5 × 20000) |
| `MEGASCON-384` | 8192 B | 150.5 k | 18.4 | 74.7 µs | 109.6 | 61720 (5 × 12344) |
| `MEGASCON-384` | 16384 B | 298.9 k | 18.2 | 148 µs | 110.4 | 32390 (5 × 6478) |
| `MEGASCON-384` | 65536 B | 1.19 M | 18.2 | 592 µs | 110.7 | 8385 (5 × 1677) |
| `MEGASCON-384-XOF-256` | 32 B | 3279 | 102.5 | 1.62 µs | 19.8 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-256` | 128 B | 3276 | 25.6 | 1.62 µs | 79.1 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-256` | 512 B | 12.4 k | 24.3 | 6.16 µs | 83.1 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-256` | 1024 B | 21.7 k | 21.2 | 10.7 µs | 95.4 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-256` | 4096 B | 79.7 k | 19.5 | 39.5 µs | 103.6 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-256` | 8192 B | 160.0 k | 19.5 | 79.3 µs | 103.3 | 58660 (5 × 11732) |
| `MEGASCON-384-XOF-256` | 16384 B | 317.6 k | 19.4 | 157 µs | 104.2 | 30780 (5 × 6156) |
| `MEGASCON-384-XOF-256` | 65536 B | 1.27 M | 19.3 | 627 µs | 104.5 | 7940 (5 × 1588) |
| `MEGASCON-384-XOF-1024` | 32 B | 3487 | 109.0 | 1.72 µs | 18.6 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-1024` | 128 B | 3483 | 27.2 | 1.72 µs | 74.6 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-1024` | 512 B | 12.6 k | 24.7 | 6.26 µs | 81.8 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-1024` | 1024 B | 21.9 k | 21.3 | 10.8 µs | 94.8 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-1024` | 4096 B | 79.9 k | 19.5 | 39.6 µs | 103.4 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-1024` | 8192 B | 160.3 k | 19.6 | 79.4 µs | 103.2 | 47590 (5 × 9518) |
| `MEGASCON-384-XOF-1024` | 16384 B | 317.8 k | 19.4 | 157 µs | 104.1 | 30705 (5 × 6141) |
| `MEGASCON-384-XOF-1024` | 65536 B | 1.27 M | 19.3 | 627 µs | 104.5 | 7900 (5 × 1580) |
| `MEGASCON-384-XOF-2048` | 32 B | 6552 | 204.8 | 3.19 µs | 10.0 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-2048` | 128 B | 6557 | 51.2 | 3.19 µs | 40.1 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-2048` | 512 B | 15.8 k | 30.8 | 7.77 µs | 65.9 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-2048` | 1024 B | 24.9 k | 24.4 | 12.3 µs | 83.3 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-2048` | 4096 B | 83.1 k | 20.3 | 41.1 µs | 99.7 | 100000 (5 × 20000) |
| `MEGASCON-384-XOF-2048` | 8192 B | 163.3 k | 19.9 | 80.8 µs | 101.4 | 57330 (5 × 11466) |
| `MEGASCON-384-XOF-2048` | 16384 B | 320.9 k | 19.6 | 159 µs | 103.1 | 30475 (5 × 6095) |
| `MEGASCON-384-XOF-2048` | 65536 B | 1.27 M | 19.4 | 629 µs | 104.3 | 7795 (5 × 1559) |
| `MEGASCON-512` | 32 B | 3016 | 94.2 | 1.48 µs | 21.6 | 100000 (5 × 20000) |
| `MEGASCON-512` | 128 B | 5900 | 46.1 | 2.91 µs | 44.1 | 100000 (5 × 20000) |
| `MEGASCON-512` | 512 B | 14.5 k | 28.3 | 7.13 µs | 71.8 | 100000 (5 × 20000) |
| `MEGASCON-512` | 1024 B | 26.0 k | 25.3 | 12.8 µs | 80.2 | 100000 (5 × 20000) |
| `MEGASCON-512` | 4096 B | 94.6 k | 23.1 | 46.6 µs | 87.9 | 93720 (5 × 18744) |
| `MEGASCON-512` | 8192 B | 187.0 k | 22.8 | 92.1 µs | 88.9 | 50905 (5 × 10181) |
| `MEGASCON-512` | 16384 B | 372.0 k | 22.7 | 183 µs | 89.4 | 26520 (5 × 5304) |
| `MEGASCON-512` | 65536 B | 1.48 M | 22.7 | 731 µs | 89.6 | 6795 (5 × 1359) |
| `MEGASCON-512-XOF-256` | 32 B | 3235 | 101.1 | 1.59 µs | 20.1 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-256` | 128 B | 6254 | 48.9 | 3.08 µs | 41.6 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-256` | 512 B | 15.4 k | 30.0 | 7.55 µs | 67.8 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-256` | 1024 B | 27.4 k | 26.7 | 13.5 µs | 76.1 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-256` | 4096 B | 99.8 k | 24.4 | 49.1 µs | 83.4 | 89425 (5 × 17885) |
| `MEGASCON-512-XOF-256` | 8192 B | 197.1 k | 24.1 | 97 µs | 84.5 | 48475 (5 × 9695) |
| `MEGASCON-512-XOF-256` | 16384 B | 391.7 k | 23.9 | 193 µs | 85.0 | 25245 (5 × 5049) |
| `MEGASCON-512-XOF-256` | 65536 B | 1.56 M | 23.8 | 767 µs | 85.4 | 6475 (5 × 1295) |
| `MEGASCON-512-XOF-1024` | 32 B | 3438 | 107.4 | 1.69 µs | 19.0 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-1024` | 128 B | 6460 | 50.5 | 3.18 µs | 40.3 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-1024` | 512 B | 15.6 k | 30.4 | 7.64 µs | 67.0 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-1024` | 1024 B | 27.6 k | 26.9 | 13.6 µs | 75.5 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-1024` | 4096 B | 100.0 k | 24.4 | 49.2 µs | 83.3 | 89865 (5 × 17973) |
| `MEGASCON-512-XOF-1024` | 8192 B | 197.2 k | 24.1 | 97 µs | 84.4 | 48335 (5 × 9667) |
| `MEGASCON-512-XOF-1024` | 16384 B | 392.2 k | 23.9 | 193 µs | 84.9 | 25230 (5 × 5046) |
| `MEGASCON-512-XOF-1024` | 65536 B | 1.56 M | 23.8 | 767 µs | 85.4 | 6475 (5 × 1295) |
| `MEGASCON-512-XOF-2048` | 32 B | 6505 | 203.3 | 3.15 µs | 10.1 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-2048` | 128 B | 9554 | 74.6 | 4.65 µs | 27.5 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-2048` | 512 B | 18.6 k | 36.4 | 9.11 µs | 56.2 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-2048` | 1024 B | 30.7 k | 30.0 | 15.1 µs | 68.0 | 100000 (5 × 20000) |
| `MEGASCON-512-XOF-2048` | 4096 B | 103.1 k | 25.2 | 50.7 µs | 80.8 | 87210 (5 × 17442) |
| `MEGASCON-512-XOF-2048` | 8192 B | 200.3 k | 24.4 | 98.5 µs | 83.1 | 47665 (5 × 9533) |
| `MEGASCON-512-XOF-2048` | 16384 B | 395.1 k | 24.1 | 194 µs | 84.3 | 25020 (5 × 5004) |
| `MEGASCON-512-XOF-2048` | 65536 B | 1.56 M | 23.9 | 769 µs | 85.2 | 6460 (5 × 1292) |
| `MEGASCON-768` | 32 B | 3266 | 102.1 | 1.61 µs | 19.9 | 100000 (5 × 20000) |
| `MEGASCON-768` | 128 B | 3289 | 25.7 | 1.62 µs | 79.0 | 100000 (5 × 20000) |
| `MEGASCON-768` | 512 B | 12.6 k | 24.5 | 6.21 µs | 82.4 | 100000 (5 × 20000) |
| `MEGASCON-768` | 1024 B | 21.9 k | 21.3 | 10.8 µs | 94.9 | 100000 (5 × 20000) |
| `MEGASCON-768` | 4096 B | 83.7 k | 20.4 | 41.4 µs | 99.0 | 100000 (5 × 20000) |
| `MEGASCON-768` | 8192 B | 167.7 k | 20.5 | 82.9 µs | 98.8 | 56080 (5 × 11216) |
| `MEGASCON-768` | 16384 B | 336.3 k | 20.5 | 166 µs | 98.6 | 28900 (5 × 5780) |
| `MEGASCON-768` | 65536 B | 1.35 M | 20.6 | 666 µs | 98.5 | 7455 (5 × 1491) |
| `MEGASCON-1024` | 32 B | 3264 | 102.0 | 1.6 µs | 20.0 | 100000 (5 × 20000) |
| `MEGASCON-1024` | 128 B | 6370 | 49.8 | 3.13 µs | 40.9 | 100000 (5 × 20000) |
| `MEGASCON-1024` | 512 B | 15.7 k | 30.6 | 7.67 µs | 66.8 | 100000 (5 × 20000) |
| `MEGASCON-1024` | 1024 B | 28.0 k | 27.3 | 13.7 µs | 74.6 | 100000 (5 × 20000) |
| `MEGASCON-1024` | 4096 B | 108.2 k | 26.4 | 53.1 µs | 77.2 | 83805 (5 × 16761) |
| `MEGASCON-1024` | 8192 B | 213.7 k | 26.1 | 105 µs | 78.1 | 44940 (5 × 8988) |
| `MEGASCON-1024` | 16384 B | 425.1 k | 25.9 | 209 µs | 78.5 | 23330 (5 × 4666) |
| `MEGASCON-1024` | 65536 B | 1.70 M | 25.9 | 835 µs | 78.5 | 5890 (5 × 1178) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `MEGASCON-384` | hash_32 | 12497 | 1672 KiB | 5216 KiB |
| `MEGASCON-384` | hash_128 | 12497 | 1672 KiB | 5216 KiB |
| `MEGASCON-384` | hash_512 | 12497 | 1684 KiB | 14592 KiB |
| `MEGASCON-384` | hash_1024 | 12497 | 1632 KiB | 23952 KiB |
| `MEGASCON-384` | hash_4096 | 12497 | 1680 KiB | 83320 KiB |
| `MEGASCON-384` | hash_8192 | 12497 | 1604 KiB | 102244 KiB |
| `MEGASCON-384` | hash_16384 | 12497 | 1696 KiB | 106200 KiB |
| `MEGASCON-384` | hash_65536 | 12497 | 1752 KiB | 109468 KiB |
| `MEGASCON-384-XOF-256` | hash_32 | 12737 | 1676 KiB | 5180 KiB |
| `MEGASCON-384-XOF-256` | hash_128 | 12737 | 1684 KiB | 5208 KiB |
| `MEGASCON-384-XOF-256` | hash_512 | 12737 | 1652 KiB | 14592 KiB |
| `MEGASCON-384-XOF-256` | hash_1024 | 12737 | 1660 KiB | 23920 KiB |
| `MEGASCON-384-XOF-256` | hash_4096 | 12737 | 1668 KiB | 83308 KiB |
| `MEGASCON-384-XOF-256` | hash_8192 | 12737 | 1692 KiB | 97308 KiB |
| `MEGASCON-384-XOF-256` | hash_16384 | 12737 | 1656 KiB | 101004 KiB |
| `MEGASCON-384-XOF-256` | hash_65536 | 12737 | 1736 KiB | 103768 KiB |
| `MEGASCON-384-XOF-1024` | hash_32 | 12745 | 1692 KiB | 5196 KiB |
| `MEGASCON-384-XOF-1024` | hash_128 | 12745 | 1664 KiB | 5212 KiB |
| `MEGASCON-384-XOF-1024` | hash_512 | 12745 | 1684 KiB | 14564 KiB |
| `MEGASCON-384-XOF-1024` | hash_1024 | 12745 | 1680 KiB | 23968 KiB |
| `MEGASCON-384-XOF-1024` | hash_4096 | 12745 | 1692 KiB | 83348 KiB |
| `MEGASCON-384-XOF-1024` | hash_8192 | 12745 | 1668 KiB | 79292 KiB |
| `MEGASCON-384-XOF-1024` | hash_16384 | 12745 | 1688 KiB | 100728 KiB |
| `MEGASCON-384-XOF-1024` | hash_65536 | 12745 | 1732 KiB | 103232 KiB |
| `MEGASCON-384-XOF-2048` | hash_32 | 12745 | 1680 KiB | 5212 KiB |
| `MEGASCON-384-XOF-2048` | hash_128 | 12745 | 1656 KiB | 5212 KiB |
| `MEGASCON-384-XOF-2048` | hash_512 | 12745 | 1688 KiB | 14596 KiB |
| `MEGASCON-384-XOF-2048` | hash_1024 | 12745 | 1672 KiB | 23960 KiB |
| `MEGASCON-384-XOF-2048` | hash_4096 | 12745 | 1692 KiB | 83332 KiB |
| `MEGASCON-384-XOF-2048` | hash_8192 | 12745 | 1700 KiB | 95128 KiB |
| `MEGASCON-384-XOF-2048` | hash_16384 | 12745 | 1688 KiB | 99988 KiB |
| `MEGASCON-384-XOF-2048` | hash_65536 | 12745 | 1736 KiB | 101912 KiB |
| `MEGASCON-512` | hash_32 | 12497 | 1596 KiB | 4536 KiB |
| `MEGASCON-512` | hash_128 | 12497 | 1672 KiB | 7084 KiB |
| `MEGASCON-512` | hash_512 | 12497 | 1692 KiB | 14572 KiB |
| `MEGASCON-512` | hash_1024 | 12497 | 1692 KiB | 24572 KiB |
| `MEGASCON-512` | hash_4096 | 12497 | 1676 KiB | 79404 KiB |
| `MEGASCON-512` | hash_8192 | 12497 | 1696 KiB | 84668 KiB |
| `MEGASCON-512` | hash_16384 | 12497 | 1696 KiB | 87444 KiB |
| `MEGASCON-512` | hash_65536 | 12497 | 1748 KiB | 89172 KiB |
| `MEGASCON-512-XOF-256` | hash_32 | 12737 | 1680 KiB | 4588 KiB |
| `MEGASCON-512-XOF-256` | hash_128 | 12737 | 1676 KiB | 7088 KiB |
| `MEGASCON-512-XOF-256` | hash_512 | 12737 | 1672 KiB | 14576 KiB |
| `MEGASCON-512-XOF-256` | hash_1024 | 12737 | 1688 KiB | 24584 KiB |
| `MEGASCON-512-XOF-256` | hash_4096 | 12737 | 1664 KiB | 75852 KiB |
| `MEGASCON-512-XOF-256` | hash_8192 | 12737 | 1688 KiB | 80700 KiB |
| `MEGASCON-512-XOF-256` | hash_16384 | 12737 | 1704 KiB | 83328 KiB |
| `MEGASCON-512-XOF-256` | hash_65536 | 12737 | 1756 KiB | 85076 KiB |
| `MEGASCON-512-XOF-1024` | hash_32 | 12745 | 1672 KiB | 4568 KiB |
| `MEGASCON-512-XOF-1024` | hash_128 | 12745 | 1688 KiB | 7088 KiB |
| `MEGASCON-512-XOF-1024` | hash_512 | 12745 | 1672 KiB | 14596 KiB |
| `MEGASCON-512-XOF-1024` | hash_1024 | 12745 | 1652 KiB | 24592 KiB |
| `MEGASCON-512-XOF-1024` | hash_4096 | 12745 | 1668 KiB | 76164 KiB |
| `MEGASCON-512-XOF-1024` | hash_8192 | 12745 | 1680 KiB | 80484 KiB |
| `MEGASCON-512-XOF-1024` | hash_16384 | 12745 | 1684 KiB | 83284 KiB |
| `MEGASCON-512-XOF-1024` | hash_65536 | 12745 | 1748 KiB | 85068 KiB |
| `MEGASCON-512-XOF-2048` | hash_32 | 12745 | 1664 KiB | 4540 KiB |
| `MEGASCON-512-XOF-2048` | hash_128 | 12745 | 1672 KiB | 7052 KiB |
| `MEGASCON-512-XOF-2048` | hash_512 | 12745 | 1592 KiB | 14536 KiB |
| `MEGASCON-512-XOF-2048` | hash_1024 | 12745 | 1668 KiB | 24548 KiB |
| `MEGASCON-512-XOF-2048` | hash_4096 | 12745 | 1680 KiB | 74000 KiB |
| `MEGASCON-512-XOF-2048` | hash_8192 | 12745 | 1676 KiB | 79368 KiB |
| `MEGASCON-512-XOF-2048` | hash_16384 | 12745 | 1692 KiB | 82572 KiB |
| `MEGASCON-512-XOF-2048` | hash_65536 | 12745 | 1756 KiB | 84884 KiB |
| `MEGASCON-768` | hash_32 | 12825 | 1656 KiB | 4908 KiB |
| `MEGASCON-768` | hash_128 | 12825 | 1684 KiB | 4876 KiB |
| `MEGASCON-768` | hash_512 | 12825 | 1672 KiB | 13928 KiB |
| `MEGASCON-768` | hash_1024 | 12825 | 1680 KiB | 22716 KiB |
| `MEGASCON-768` | hash_4096 | 12825 | 1680 KiB | 82108 KiB |
| `MEGASCON-768` | hash_8192 | 12825 | 1608 KiB | 91840 KiB |
| `MEGASCON-768` | hash_16384 | 12825 | 1700 KiB | 94596 KiB |
| `MEGASCON-768` | hash_65536 | 12825 | 1728 KiB | 97664 KiB |
| `MEGASCON-1024` | hash_32 | 12825 | 1680 KiB | 4280 KiB |
| `MEGASCON-1024` | hash_128 | 12825 | 1672 KiB | 6768 KiB |
| `MEGASCON-1024` | hash_512 | 12825 | 1664 KiB | 13636 KiB |
| `MEGASCON-1024` | hash_1024 | 12825 | 1672 KiB | 23028 KiB |
| `MEGASCON-1024` | hash_4096 | 12825 | 1668 KiB | 70668 KiB |
| `MEGASCON-1024` | hash_8192 | 12825 | 1680 KiB | 74540 KiB |
| `MEGASCON-1024` | hash_16384 | 12825 | 1700 KiB | 76788 KiB |
| `MEGASCON-1024` | hash_65536 | 12825 | 1740 KiB | 77516 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `MEGASCON-384` | KAT log (sha256 `6e2a6764d9f7e394…`) | `kat/hash-18/MEGASCON-384.log` |
| `MEGASCON-384` | timing hash_1024 | `records/hash-18/MEGASCON-384__hash_1024.json` |
| `MEGASCON-384` | timing hash_128 | `records/hash-18/MEGASCON-384__hash_128.json` |
| `MEGASCON-384` | timing hash_16384 | `records/hash-18/MEGASCON-384__hash_16384.json` |
| `MEGASCON-384` | timing hash_32 | `records/hash-18/MEGASCON-384__hash_32.json` |
| `MEGASCON-384` | timing hash_4096 | `records/hash-18/MEGASCON-384__hash_4096.json` |
| `MEGASCON-384` | timing hash_512 | `records/hash-18/MEGASCON-384__hash_512.json` |
| `MEGASCON-384` | timing hash_65536 | `records/hash-18/MEGASCON-384__hash_65536.json` |
| `MEGASCON-384` | timing hash_8192 | `records/hash-18/MEGASCON-384__hash_8192.json` |
| `MEGASCON-384-XOF-256` | KAT log (sha256 `9a8e946e6c3c2915…`) | `kat/hash-18/MEGASCON-384-XOF-256.log` |
| `MEGASCON-384-XOF-256` | timing hash_1024 | `records/hash-18/MEGASCON-384-XOF-256__hash_1024.json` |
| `MEGASCON-384-XOF-256` | timing hash_128 | `records/hash-18/MEGASCON-384-XOF-256__hash_128.json` |
| `MEGASCON-384-XOF-256` | timing hash_16384 | `records/hash-18/MEGASCON-384-XOF-256__hash_16384.json` |
| `MEGASCON-384-XOF-256` | timing hash_32 | `records/hash-18/MEGASCON-384-XOF-256__hash_32.json` |
| `MEGASCON-384-XOF-256` | timing hash_4096 | `records/hash-18/MEGASCON-384-XOF-256__hash_4096.json` |
| `MEGASCON-384-XOF-256` | timing hash_512 | `records/hash-18/MEGASCON-384-XOF-256__hash_512.json` |
| `MEGASCON-384-XOF-256` | timing hash_65536 | `records/hash-18/MEGASCON-384-XOF-256__hash_65536.json` |
| `MEGASCON-384-XOF-256` | timing hash_8192 | `records/hash-18/MEGASCON-384-XOF-256__hash_8192.json` |
| `MEGASCON-384-XOF-1024` | KAT log (sha256 `0421f32a4195b43a…`) | `kat/hash-18/MEGASCON-384-XOF-1024.log` |
| `MEGASCON-384-XOF-1024` | timing hash_1024 | `records/hash-18/MEGASCON-384-XOF-1024__hash_1024.json` |
| `MEGASCON-384-XOF-1024` | timing hash_128 | `records/hash-18/MEGASCON-384-XOF-1024__hash_128.json` |
| `MEGASCON-384-XOF-1024` | timing hash_16384 | `records/hash-18/MEGASCON-384-XOF-1024__hash_16384.json` |
| `MEGASCON-384-XOF-1024` | timing hash_32 | `records/hash-18/MEGASCON-384-XOF-1024__hash_32.json` |
| `MEGASCON-384-XOF-1024` | timing hash_4096 | `records/hash-18/MEGASCON-384-XOF-1024__hash_4096.json` |
| `MEGASCON-384-XOF-1024` | timing hash_512 | `records/hash-18/MEGASCON-384-XOF-1024__hash_512.json` |
| `MEGASCON-384-XOF-1024` | timing hash_65536 | `records/hash-18/MEGASCON-384-XOF-1024__hash_65536.json` |
| `MEGASCON-384-XOF-1024` | timing hash_8192 | `records/hash-18/MEGASCON-384-XOF-1024__hash_8192.json` |
| `MEGASCON-384-XOF-2048` | KAT log (sha256 `cedf1093cf289b0f…`) | `kat/hash-18/MEGASCON-384-XOF-2048.log` |
| `MEGASCON-384-XOF-2048` | timing hash_1024 | `records/hash-18/MEGASCON-384-XOF-2048__hash_1024.json` |
| `MEGASCON-384-XOF-2048` | timing hash_128 | `records/hash-18/MEGASCON-384-XOF-2048__hash_128.json` |
| `MEGASCON-384-XOF-2048` | timing hash_16384 | `records/hash-18/MEGASCON-384-XOF-2048__hash_16384.json` |
| `MEGASCON-384-XOF-2048` | timing hash_32 | `records/hash-18/MEGASCON-384-XOF-2048__hash_32.json` |
| `MEGASCON-384-XOF-2048` | timing hash_4096 | `records/hash-18/MEGASCON-384-XOF-2048__hash_4096.json` |
| `MEGASCON-384-XOF-2048` | timing hash_512 | `records/hash-18/MEGASCON-384-XOF-2048__hash_512.json` |
| `MEGASCON-384-XOF-2048` | timing hash_65536 | `records/hash-18/MEGASCON-384-XOF-2048__hash_65536.json` |
| `MEGASCON-384-XOF-2048` | timing hash_8192 | `records/hash-18/MEGASCON-384-XOF-2048__hash_8192.json` |
| `MEGASCON-512` | KAT log (sha256 `2d5810f7ff614020…`) | `kat/hash-18/MEGASCON-512.log` |
| `MEGASCON-512` | timing hash_1024 | `records/hash-18/MEGASCON-512__hash_1024.json` |
| `MEGASCON-512` | timing hash_128 | `records/hash-18/MEGASCON-512__hash_128.json` |
| `MEGASCON-512` | timing hash_16384 | `records/hash-18/MEGASCON-512__hash_16384.json` |
| `MEGASCON-512` | timing hash_32 | `records/hash-18/MEGASCON-512__hash_32.json` |
| `MEGASCON-512` | timing hash_4096 | `records/hash-18/MEGASCON-512__hash_4096.json` |
| `MEGASCON-512` | timing hash_512 | `records/hash-18/MEGASCON-512__hash_512.json` |
| `MEGASCON-512` | timing hash_65536 | `records/hash-18/MEGASCON-512__hash_65536.json` |
| `MEGASCON-512` | timing hash_8192 | `records/hash-18/MEGASCON-512__hash_8192.json` |
| `MEGASCON-512-XOF-256` | KAT log (sha256 `3dc92e08155a4f15…`) | `kat/hash-18/MEGASCON-512-XOF-256.log` |
| `MEGASCON-512-XOF-256` | timing hash_1024 | `records/hash-18/MEGASCON-512-XOF-256__hash_1024.json` |
| `MEGASCON-512-XOF-256` | timing hash_128 | `records/hash-18/MEGASCON-512-XOF-256__hash_128.json` |
| `MEGASCON-512-XOF-256` | timing hash_16384 | `records/hash-18/MEGASCON-512-XOF-256__hash_16384.json` |
| `MEGASCON-512-XOF-256` | timing hash_32 | `records/hash-18/MEGASCON-512-XOF-256__hash_32.json` |
| `MEGASCON-512-XOF-256` | timing hash_4096 | `records/hash-18/MEGASCON-512-XOF-256__hash_4096.json` |
| `MEGASCON-512-XOF-256` | timing hash_512 | `records/hash-18/MEGASCON-512-XOF-256__hash_512.json` |
| `MEGASCON-512-XOF-256` | timing hash_65536 | `records/hash-18/MEGASCON-512-XOF-256__hash_65536.json` |
| `MEGASCON-512-XOF-256` | timing hash_8192 | `records/hash-18/MEGASCON-512-XOF-256__hash_8192.json` |
| `MEGASCON-512-XOF-1024` | KAT log (sha256 `87175b627da2ad27…`) | `kat/hash-18/MEGASCON-512-XOF-1024.log` |
| `MEGASCON-512-XOF-1024` | timing hash_1024 | `records/hash-18/MEGASCON-512-XOF-1024__hash_1024.json` |
| `MEGASCON-512-XOF-1024` | timing hash_128 | `records/hash-18/MEGASCON-512-XOF-1024__hash_128.json` |
| `MEGASCON-512-XOF-1024` | timing hash_16384 | `records/hash-18/MEGASCON-512-XOF-1024__hash_16384.json` |
| `MEGASCON-512-XOF-1024` | timing hash_32 | `records/hash-18/MEGASCON-512-XOF-1024__hash_32.json` |
| `MEGASCON-512-XOF-1024` | timing hash_4096 | `records/hash-18/MEGASCON-512-XOF-1024__hash_4096.json` |
| `MEGASCON-512-XOF-1024` | timing hash_512 | `records/hash-18/MEGASCON-512-XOF-1024__hash_512.json` |
| `MEGASCON-512-XOF-1024` | timing hash_65536 | `records/hash-18/MEGASCON-512-XOF-1024__hash_65536.json` |
| `MEGASCON-512-XOF-1024` | timing hash_8192 | `records/hash-18/MEGASCON-512-XOF-1024__hash_8192.json` |
| `MEGASCON-512-XOF-2048` | KAT log (sha256 `09a12a0a1379a3df…`) | `kat/hash-18/MEGASCON-512-XOF-2048.log` |
| `MEGASCON-512-XOF-2048` | timing hash_1024 | `records/hash-18/MEGASCON-512-XOF-2048__hash_1024.json` |
| `MEGASCON-512-XOF-2048` | timing hash_128 | `records/hash-18/MEGASCON-512-XOF-2048__hash_128.json` |
| `MEGASCON-512-XOF-2048` | timing hash_16384 | `records/hash-18/MEGASCON-512-XOF-2048__hash_16384.json` |
| `MEGASCON-512-XOF-2048` | timing hash_32 | `records/hash-18/MEGASCON-512-XOF-2048__hash_32.json` |
| `MEGASCON-512-XOF-2048` | timing hash_4096 | `records/hash-18/MEGASCON-512-XOF-2048__hash_4096.json` |
| `MEGASCON-512-XOF-2048` | timing hash_512 | `records/hash-18/MEGASCON-512-XOF-2048__hash_512.json` |
| `MEGASCON-512-XOF-2048` | timing hash_65536 | `records/hash-18/MEGASCON-512-XOF-2048__hash_65536.json` |
| `MEGASCON-512-XOF-2048` | timing hash_8192 | `records/hash-18/MEGASCON-512-XOF-2048__hash_8192.json` |
| `MEGASCON-768` | KAT log (sha256 `00b0de356891ba99…`) | `kat/hash-18/MEGASCON-768.log` |
| `MEGASCON-768` | timing hash_1024 | `records/hash-18/MEGASCON-768__hash_1024.json` |
| `MEGASCON-768` | timing hash_128 | `records/hash-18/MEGASCON-768__hash_128.json` |
| `MEGASCON-768` | timing hash_16384 | `records/hash-18/MEGASCON-768__hash_16384.json` |
| `MEGASCON-768` | timing hash_32 | `records/hash-18/MEGASCON-768__hash_32.json` |
| `MEGASCON-768` | timing hash_4096 | `records/hash-18/MEGASCON-768__hash_4096.json` |
| `MEGASCON-768` | timing hash_512 | `records/hash-18/MEGASCON-768__hash_512.json` |
| `MEGASCON-768` | timing hash_65536 | `records/hash-18/MEGASCON-768__hash_65536.json` |
| `MEGASCON-768` | timing hash_8192 | `records/hash-18/MEGASCON-768__hash_8192.json` |
| `MEGASCON-1024` | KAT log (sha256 `5b6535b12b36bac0…`) | `kat/hash-18/MEGASCON-1024.log` |
| `MEGASCON-1024` | timing hash_1024 | `records/hash-18/MEGASCON-1024__hash_1024.json` |
| `MEGASCON-1024` | timing hash_128 | `records/hash-18/MEGASCON-1024__hash_128.json` |
| `MEGASCON-1024` | timing hash_16384 | `records/hash-18/MEGASCON-1024__hash_16384.json` |
| `MEGASCON-1024` | timing hash_32 | `records/hash-18/MEGASCON-1024__hash_32.json` |
| `MEGASCON-1024` | timing hash_4096 | `records/hash-18/MEGASCON-1024__hash_4096.json` |
| `MEGASCON-1024` | timing hash_512 | `records/hash-18/MEGASCON-1024__hash_512.json` |
| `MEGASCON-1024` | timing hash_65536 | `records/hash-18/MEGASCON-1024__hash_65536.json` |
| `MEGASCON-1024` | timing hash_8192 | `records/hash-18/MEGASCON-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

