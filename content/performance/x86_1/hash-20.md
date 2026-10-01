<!-- synchronized from harness: hash-20/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-20</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101537013422968832.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-20.md">arm_1</a></p>

# hash-20 Mozi Hash Function — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Mozi Hash Function
- Implementation versions measured: reference
- Parameter sets: `MOZI-384`, `MOZI-384-XOF-256`, `MOZI-384-XOF-1024`, `MOZI-384-XOF-2048`, `MOZI-512`, `MOZI-512-XOF-256`, `MOZI-512-XOF-1024`, `MOZI-512-XOF-2048`, `MOZI-768`, `MOZI-1024`
- Security evaluation: [hash-20 report](../../reports/hash-20.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-20/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `MOZI-384` | guide | PASS |
| `MOZI-384-XOF-256` | guide | PASS |
| `MOZI-384-XOF-1024` | guide | PASS |
| `MOZI-384-XOF-2048` | guide | PASS |
| `MOZI-512` | guide | PASS |
| `MOZI-512-XOF-256` | guide | PASS |
| `MOZI-512-XOF-1024` | guide | PASS |
| `MOZI-512-XOF-2048` | guide | PASS |
| `MOZI-768` | guide | PASS |
| `MOZI-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `MOZI-384` | 32 B | 3139 | 98.1 | 1.56 µs | 20.6 | 100000 (5 × 20000) |
| `MOZI-384` | 128 B | 3146 | 24.6 | 1.56 µs | 82.1 | 100000 (5 × 20000) |
| `MOZI-384` | 512 B | 12.1 k | 23.6 | 5.98 µs | 85.7 | 100000 (5 × 20000) |
| `MOZI-384` | 1024 B | 21.1 k | 20.6 | 10.4 µs | 98.1 | 100000 (5 × 20000) |
| `MOZI-384` | 4096 B | 77.3 k | 18.9 | 38.4 µs | 106.7 | 100000 (5 × 20000) |
| `MOZI-384` | 8192 B | 155.2 k | 19.0 | 77.1 µs | 106.3 | 57565 (5 × 11513) |
| `MOZI-384` | 16384 B | 308.1 k | 18.8 | 153 µs | 107.1 | 31430 (5 × 6286) |
| `MOZI-384` | 65536 B | 1.23 M | 18.8 | 610 µs | 107.4 | 7710 (5 × 1542) |
| `MOZI-384-XOF-256` | 32 B | 3323 | 103.9 | 1.65 µs | 19.4 | 100000 (5 × 20000) |
| `MOZI-384-XOF-256` | 128 B | 3402 | 26.6 | 1.68 µs | 76.1 | 100000 (5 × 20000) |
| `MOZI-384-XOF-256` | 512 B | 13.0 k | 25.3 | 6.4 µs | 80.0 | 100000 (5 × 20000) |
| `MOZI-384-XOF-256` | 1024 B | 22.0 k | 21.5 | 10.9 µs | 94.0 | 100000 (5 × 20000) |
| `MOZI-384-XOF-256` | 4096 B | 80.8 k | 19.7 | 40 µs | 102.3 | 100000 (5 × 20000) |
| `MOZI-384-XOF-256` | 8192 B | 162.0 k | 19.8 | 80.3 µs | 102.0 | 56330 (5 × 11266) |
| `MOZI-384-XOF-256` | 16384 B | 321.0 k | 19.6 | 159 µs | 103.0 | 30180 (5 × 6036) |
| `MOZI-384-XOF-256` | 65536 B | 1.28 M | 19.5 | 634 µs | 103.4 | 7830 (5 × 1566) |
| `MOZI-384-XOF-1024` | 32 B | 3535 | 110.5 | 2.34 µs | 13.7 | 100000 (5 × 20000) |
| `MOZI-384-XOF-1024` | 128 B | 3540 | 27.7 | 1.75 µs | 73.2 | 100000 (5 × 20000) |
| `MOZI-384-XOF-1024` | 512 B | 12.9 k | 25.3 | 6.39 µs | 80.1 | 100000 (5 × 20000) |
| `MOZI-384-XOF-1024` | 1024 B | 22.4 k | 21.9 | 11.1 µs | 92.4 | 100000 (5 × 20000) |
| `MOZI-384-XOF-1024` | 4096 B | 81.0 k | 19.8 | 40.2 µs | 102.0 | 100000 (5 × 20000) |
| `MOZI-384-XOF-1024` | 8192 B | 162.4 k | 19.8 | 80.5 µs | 101.7 | 55375 (5 × 11075) |
| `MOZI-384-XOF-1024` | 16384 B | 321.5 k | 19.6 | 159 µs | 102.8 | 30140 (5 × 6028) |
| `MOZI-384-XOF-1024` | 65536 B | 1.28 M | 19.5 | 633 µs | 103.5 | 7630 (5 × 1526) |
| `MOZI-384-XOF-2048` | 32 B | 6711 | 209.7 | 3.26 µs | 9.8 | 100000 (5 × 20000) |
| `MOZI-384-XOF-2048` | 128 B | 6720 | 52.5 | 3.27 µs | 39.1 | 100000 (5 × 20000) |
| `MOZI-384-XOF-2048` | 512 B | 16.0 k | 31.3 | 7.89 µs | 64.9 | 100000 (5 × 20000) |
| `MOZI-384-XOF-2048` | 1024 B | 25.4 k | 24.8 | 12.5 µs | 81.9 | 100000 (5 × 20000) |
| `MOZI-384-XOF-2048` | 4096 B | 84.7 k | 20.7 | 41.9 µs | 97.7 | 99385 (5 × 19877) |
| `MOZI-384-XOF-2048` | 8192 B | 165.4 k | 20.2 | 81.9 µs | 100.0 | 55640 (5 × 11128) |
| `MOZI-384-XOF-2048` | 16384 B | 324.6 k | 19.8 | 161 µs | 101.8 | 29170 (5 × 5834) |
| `MOZI-384-XOF-2048` | 65536 B | 1.28 M | 19.5 | 635 µs | 103.3 | 7310 (5 × 1462) |
| `MOZI-512` | 32 B | 3108 | 97.1 | 1.53 µs | 20.9 | 100000 (5 × 20000) |
| `MOZI-512` | 128 B | 6154 | 48.1 | 3.03 µs | 42.3 | 100000 (5 × 20000) |
| `MOZI-512` | 512 B | 15.2 k | 29.7 | 7.48 µs | 68.4 | 100000 (5 × 20000) |
| `MOZI-512` | 1024 B | 26.8 k | 26.2 | 13.2 µs | 77.6 | 100000 (5 × 20000) |
| `MOZI-512` | 4096 B | 99.9 k | 24.4 | 49.2 µs | 83.3 | 88540 (5 × 17708) |
| `MOZI-512` | 8192 B | 193.3 k | 23.6 | 95.3 µs | 86.0 | 46075 (5 × 9215) |
| `MOZI-512` | 16384 B | 384.1 k | 23.4 | 189 µs | 86.5 | 23010 (5 × 4602) |
| `MOZI-512` | 65536 B | 1.53 M | 23.4 | 755 µs | 86.9 | 6540 (5 × 1308) |
| `MOZI-512-XOF-256` | 32 B | 3351 | 104.7 | 1.65 µs | 19.4 | 100000 (5 × 20000) |
| `MOZI-512-XOF-256` | 128 B | 6494 | 50.7 | 3.19 µs | 40.1 | 100000 (5 × 20000) |
| `MOZI-512-XOF-256` | 512 B | 15.6 k | 30.5 | 7.68 µs | 66.7 | 100000 (5 × 20000) |
| `MOZI-512-XOF-256` | 1024 B | 27.8 k | 27.2 | 13.7 µs | 74.8 | 100000 (5 × 20000) |
| `MOZI-512-XOF-256` | 4096 B | 101.0 k | 24.7 | 49.7 µs | 82.3 | 86170 (5 × 17234) |
| `MOZI-512-XOF-256` | 8192 B | 201.2 k | 24.6 | 99 µs | 82.8 | 47070 (5 × 9414) |
| `MOZI-512-XOF-256` | 16384 B | 396.2 k | 24.2 | 195 µs | 84.0 | 24820 (5 × 4964) |
| `MOZI-512-XOF-256` | 65536 B | 1.58 M | 24.1 | 776 µs | 84.4 | 6375 (5 × 1275) |
| `MOZI-512-XOF-1024` | 32 B | 3475 | 108.6 | 1.71 µs | 18.7 | 100000 (5 × 20000) |
| `MOZI-512-XOF-1024` | 128 B | 6676 | 52.2 | 3.28 µs | 39.0 | 100000 (5 × 20000) |
| `MOZI-512-XOF-1024` | 512 B | 15.8 k | 30.9 | 7.77 µs | 65.9 | 100000 (5 × 20000) |
| `MOZI-512-XOF-1024` | 1024 B | 28.3 k | 27.6 | 13.9 µs | 73.7 | 100000 (5 × 20000) |
| `MOZI-512-XOF-1024` | 4096 B | 101.4 k | 24.8 | 49.9 µs | 82.0 | 86575 (5 × 17315) |
| `MOZI-512-XOF-1024` | 8192 B | 199.6 k | 24.4 | 98.3 µs | 83.4 | 46810 (5 × 9362) |
| `MOZI-512-XOF-1024` | 16384 B | 399.8 k | 24.4 | 197 µs | 83.2 | 24755 (5 × 4951) |
| `MOZI-512-XOF-1024` | 65536 B | 1.58 M | 24.0 | 776 µs | 84.5 | 6115 (5 × 1223) |
| `MOZI-512-XOF-2048` | 32 B | 6604 | 206.4 | 3.21 µs | 10.0 | 100000 (5 × 20000) |
| `MOZI-512-XOF-2048` | 128 B | 9770 | 76.3 | 4.76 µs | 26.9 | 100000 (5 × 20000) |
| `MOZI-512-XOF-2048` | 512 B | 18.9 k | 37.0 | 9.26 µs | 55.3 | 100000 (5 × 20000) |
| `MOZI-512-XOF-2048` | 1024 B | 31.2 k | 30.4 | 15.3 µs | 67.0 | 100000 (5 × 20000) |
| `MOZI-512-XOF-2048` | 4096 B | 104.3 k | 25.5 | 51.3 µs | 79.8 | 84720 (5 × 16944) |
| `MOZI-512-XOF-2048` | 8192 B | 202.7 k | 24.7 | 99.7 µs | 82.1 | 46785 (5 × 9357) |
| `MOZI-512-XOF-2048` | 16384 B | 399.4 k | 24.4 | 197 µs | 83.3 | 23720 (5 × 4744) |
| `MOZI-512-XOF-2048` | 65536 B | 1.58 M | 24.1 | 777 µs | 84.4 | 6160 (5 × 1232) |
| `MOZI-768` | 32 B | 3621 | 113.2 | 1.78 µs | 18.0 | 100000 (5 × 20000) |
| `MOZI-768` | 128 B | 3655 | 28.6 | 1.8 µs | 71.3 | 100000 (5 × 20000) |
| `MOZI-768` | 512 B | 14.0 k | 27.4 | 6.91 µs | 74.1 | 100000 (5 × 20000) |
| `MOZI-768` | 1024 B | 24.6 k | 24.0 | 12.1 µs | 84.8 | 100000 (5 × 20000) |
| `MOZI-768` | 4096 B | 93.0 k | 22.7 | 45.9 µs | 89.3 | 91700 (5 × 18340) |
| `MOZI-768` | 8192 B | 186.8 k | 22.8 | 92.1 µs | 89.0 | 48745 (5 × 9749) |
| `MOZI-768` | 16384 B | 374.0 k | 22.8 | 185 µs | 88.8 | 23815 (5 × 4763) |
| `MOZI-768` | 65536 B | 1.50 M | 22.9 | 739 µs | 88.7 | 6745 (5 × 1349) |
| `MOZI-1024` | 32 B | 3611 | 112.9 | 1.77 µs | 18.1 | 100000 (5 × 20000) |
| `MOZI-1024` | 128 B | 7107 | 55.5 | 3.48 µs | 36.8 | 100000 (5 × 20000) |
| `MOZI-1024` | 512 B | 17.4 k | 34.1 | 8.53 µs | 60.1 | 100000 (5 × 20000) |
| `MOZI-1024` | 1024 B | 31.4 k | 30.7 | 15.4 µs | 66.6 | 100000 (5 × 20000) |
| `MOZI-1024` | 4096 B | 121.3 k | 29.6 | 59.4 µs | 68.9 | 74150 (5 × 14830) |
| `MOZI-1024` | 8192 B | 237.7 k | 29.0 | 116 µs | 70.3 | 35340 (5 × 7068) |
| `MOZI-1024` | 16384 B | 472.9 k | 28.9 | 232 µs | 70.7 | 20965 (5 × 4193) |
| `MOZI-1024` | 65536 B | 1.89 M | 28.8 | 926 µs | 70.8 | 5250 (5 × 1050) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `MOZI-384` | hash_32 | 12577 | 1692 KiB | 5208 KiB |
| `MOZI-384` | hash_128 | 12577 | 1688 KiB | 5192 KiB |
| `MOZI-384` | hash_512 | 12577 | 1668 KiB | 14576 KiB |
| `MOZI-384` | hash_1024 | 12577 | 1688 KiB | 23944 KiB |
| `MOZI-384` | hash_4096 | 12577 | 1664 KiB | 83352 KiB |
| `MOZI-384` | hash_8192 | 12577 | 1608 KiB | 95484 KiB |
| `MOZI-384` | hash_16384 | 12577 | 1688 KiB | 103064 KiB |
| `MOZI-384` | hash_65536 | 12577 | 1744 KiB | 100844 KiB |
| `MOZI-384-XOF-256` | hash_32 | 12849 | 1668 KiB | 5216 KiB |
| `MOZI-384-XOF-256` | hash_128 | 12849 | 1644 KiB | 5212 KiB |
| `MOZI-384-XOF-256` | hash_512 | 12849 | 1688 KiB | 14584 KiB |
| `MOZI-384-XOF-256` | hash_1024 | 12849 | 1652 KiB | 23968 KiB |
| `MOZI-384-XOF-256` | hash_4096 | 12849 | 1660 KiB | 83360 KiB |
| `MOZI-384-XOF-256` | hash_8192 | 12849 | 1664 KiB | 93524 KiB |
| `MOZI-384-XOF-256` | hash_16384 | 12849 | 1696 KiB | 99072 KiB |
| `MOZI-384-XOF-256` | hash_65536 | 12849 | 1752 KiB | 102380 KiB |
| `MOZI-384-XOF-1024` | hash_32 | 12849 | 1688 KiB | 5192 KiB |
| `MOZI-384-XOF-1024` | hash_128 | 12849 | 1684 KiB | 5188 KiB |
| `MOZI-384-XOF-1024` | hash_512 | 12849 | 1680 KiB | 14596 KiB |
| `MOZI-384-XOF-1024` | hash_1024 | 12849 | 1692 KiB | 23948 KiB |
| `MOZI-384-XOF-1024` | hash_4096 | 12849 | 1688 KiB | 83336 KiB |
| `MOZI-384-XOF-1024` | hash_8192 | 12849 | 1688 KiB | 91960 KiB |
| `MOZI-384-XOF-1024` | hash_16384 | 12849 | 1704 KiB | 98948 KiB |
| `MOZI-384-XOF-1024` | hash_65536 | 12849 | 1736 KiB | 99808 KiB |
| `MOZI-384-XOF-2048` | hash_32 | 12849 | 1692 KiB | 5196 KiB |
| `MOZI-384-XOF-2048` | hash_128 | 12849 | 1688 KiB | 5196 KiB |
| `MOZI-384-XOF-2048` | hash_512 | 12849 | 1680 KiB | 14560 KiB |
| `MOZI-384-XOF-2048` | hash_1024 | 12849 | 1640 KiB | 23960 KiB |
| `MOZI-384-XOF-2048` | hash_4096 | 12849 | 1676 KiB | 82832 KiB |
| `MOZI-384-XOF-2048` | hash_8192 | 12849 | 1668 KiB | 92404 KiB |
| `MOZI-384-XOF-2048` | hash_16384 | 12849 | 1704 KiB | 95800 KiB |
| `MOZI-384-XOF-2048` | hash_65536 | 12849 | 1752 KiB | 95708 KiB |
| `MOZI-512` | hash_32 | 12513 | 1684 KiB | 4568 KiB |
| `MOZI-512` | hash_128 | 12513 | 1668 KiB | 7068 KiB |
| `MOZI-512` | hash_512 | 12513 | 1688 KiB | 14568 KiB |
| `MOZI-512` | hash_1024 | 12513 | 1684 KiB | 24572 KiB |
| `MOZI-512` | hash_4096 | 12513 | 1644 KiB | 75108 KiB |
| `MOZI-512` | hash_8192 | 12513 | 1680 KiB | 76824 KiB |
| `MOZI-512` | hash_16384 | 12513 | 1696 KiB | 76120 KiB |
| `MOZI-512` | hash_65536 | 12513 | 1724 KiB | 85876 KiB |
| `MOZI-512-XOF-256` | hash_32 | 12849 | 1684 KiB | 4560 KiB |
| `MOZI-512-XOF-256` | hash_128 | 12849 | 1692 KiB | 7068 KiB |
| `MOZI-512-XOF-256` | hash_512 | 12849 | 1668 KiB | 14592 KiB |
| `MOZI-512-XOF-256` | hash_1024 | 12849 | 1680 KiB | 24560 KiB |
| `MOZI-512-XOF-256` | hash_4096 | 12849 | 1684 KiB | 73120 KiB |
| `MOZI-512-XOF-256` | hash_8192 | 12849 | 1700 KiB | 78440 KiB |
| `MOZI-512-XOF-256` | hash_16384 | 12849 | 1700 KiB | 81936 KiB |
| `MOZI-512-XOF-256` | hash_65536 | 12849 | 1692 KiB | 83792 KiB |
| `MOZI-512-XOF-1024` | hash_32 | 12849 | 1684 KiB | 4560 KiB |
| `MOZI-512-XOF-1024` | hash_128 | 12849 | 1668 KiB | 7084 KiB |
| `MOZI-512-XOF-1024` | hash_512 | 12849 | 1688 KiB | 14568 KiB |
| `MOZI-512-XOF-1024` | hash_1024 | 12849 | 1668 KiB | 24548 KiB |
| `MOZI-512-XOF-1024` | hash_4096 | 12849 | 1664 KiB | 73488 KiB |
| `MOZI-512-XOF-1024` | hash_8192 | 12849 | 1680 KiB | 78024 KiB |
| `MOZI-512-XOF-1024` | hash_16384 | 12849 | 1700 KiB | 81744 KiB |
| `MOZI-512-XOF-1024` | hash_65536 | 12849 | 1728 KiB | 80472 KiB |
| `MOZI-512-XOF-2048` | hash_32 | 12849 | 1692 KiB | 4568 KiB |
| `MOZI-512-XOF-2048` | hash_128 | 12849 | 1688 KiB | 7084 KiB |
| `MOZI-512-XOF-2048` | hash_512 | 12849 | 1672 KiB | 14584 KiB |
| `MOZI-512-XOF-2048` | hash_1024 | 12849 | 1680 KiB | 24588 KiB |
| `MOZI-512-XOF-2048` | hash_4096 | 12849 | 1572 KiB | 71868 KiB |
| `MOZI-512-XOF-2048` | hash_8192 | 12849 | 1688 KiB | 77964 KiB |
| `MOZI-512-XOF-2048` | hash_16384 | 12849 | 1704 KiB | 78388 KiB |
| `MOZI-512-XOF-2048` | hash_65536 | 12849 | 1748 KiB | 81048 KiB |
| `MOZI-768` | hash_32 | 12905 | 1680 KiB | 4872 KiB |
| `MOZI-768` | hash_128 | 12905 | 1668 KiB | 4908 KiB |
| `MOZI-768` | hash_512 | 12905 | 1680 KiB | 13936 KiB |
| `MOZI-768` | hash_1024 | 12905 | 1688 KiB | 22696 KiB |
| `MOZI-768` | hash_4096 | 12905 | 1676 KiB | 75444 KiB |
| `MOZI-768` | hash_8192 | 12905 | 1684 KiB | 80084 KiB |
| `MOZI-768` | hash_16384 | 12905 | 1700 KiB | 78264 KiB |
| `MOZI-768` | hash_65536 | 12905 | 1756 KiB | 88556 KiB |
| `MOZI-1024` | hash_32 | 12937 | 1688 KiB | 4276 KiB |
| `MOZI-1024` | hash_128 | 12937 | 1600 KiB | 6728 KiB |
| `MOZI-1024` | hash_512 | 12937 | 1660 KiB | 13652 KiB |
| `MOZI-1024` | hash_1024 | 12937 | 1672 KiB | 22992 KiB |
| `MOZI-1024` | hash_4096 | 12937 | 1680 KiB | 62736 KiB |
| `MOZI-1024` | hash_8192 | 12937 | 1684 KiB | 59016 KiB |
| `MOZI-1024` | hash_16384 | 12937 | 1708 KiB | 69172 KiB |
| `MOZI-1024` | hash_65536 | 12937 | 1736 KiB | 69348 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `MOZI-384` | KAT log (sha256 `5a4a521af8b4a0d5…`) | `kat/hash-20/MOZI-384.log` |
| `MOZI-384` | timing hash_1024 | `records/hash-20/MOZI-384__hash_1024.json` |
| `MOZI-384` | timing hash_128 | `records/hash-20/MOZI-384__hash_128.json` |
| `MOZI-384` | timing hash_16384 | `records/hash-20/MOZI-384__hash_16384.json` |
| `MOZI-384` | timing hash_32 | `records/hash-20/MOZI-384__hash_32.json` |
| `MOZI-384` | timing hash_4096 | `records/hash-20/MOZI-384__hash_4096.json` |
| `MOZI-384` | timing hash_512 | `records/hash-20/MOZI-384__hash_512.json` |
| `MOZI-384` | timing hash_65536 | `records/hash-20/MOZI-384__hash_65536.json` |
| `MOZI-384` | timing hash_8192 | `records/hash-20/MOZI-384__hash_8192.json` |
| `MOZI-384-XOF-256` | KAT log (sha256 `c52c30857954f6c3…`) | `kat/hash-20/MOZI-384-XOF-256.log` |
| `MOZI-384-XOF-256` | timing hash_1024 | `records/hash-20/MOZI-384-XOF-256__hash_1024.json` |
| `MOZI-384-XOF-256` | timing hash_128 | `records/hash-20/MOZI-384-XOF-256__hash_128.json` |
| `MOZI-384-XOF-256` | timing hash_16384 | `records/hash-20/MOZI-384-XOF-256__hash_16384.json` |
| `MOZI-384-XOF-256` | timing hash_32 | `records/hash-20/MOZI-384-XOF-256__hash_32.json` |
| `MOZI-384-XOF-256` | timing hash_4096 | `records/hash-20/MOZI-384-XOF-256__hash_4096.json` |
| `MOZI-384-XOF-256` | timing hash_512 | `records/hash-20/MOZI-384-XOF-256__hash_512.json` |
| `MOZI-384-XOF-256` | timing hash_65536 | `records/hash-20/MOZI-384-XOF-256__hash_65536.json` |
| `MOZI-384-XOF-256` | timing hash_8192 | `records/hash-20/MOZI-384-XOF-256__hash_8192.json` |
| `MOZI-384-XOF-1024` | KAT log (sha256 `5457f4b70ed5bdfd…`) | `kat/hash-20/MOZI-384-XOF-1024.log` |
| `MOZI-384-XOF-1024` | timing hash_1024 | `records/hash-20/MOZI-384-XOF-1024__hash_1024.json` |
| `MOZI-384-XOF-1024` | timing hash_128 | `records/hash-20/MOZI-384-XOF-1024__hash_128.json` |
| `MOZI-384-XOF-1024` | timing hash_16384 | `records/hash-20/MOZI-384-XOF-1024__hash_16384.json` |
| `MOZI-384-XOF-1024` | timing hash_32 | `records/hash-20/MOZI-384-XOF-1024__hash_32.json` |
| `MOZI-384-XOF-1024` | timing hash_4096 | `records/hash-20/MOZI-384-XOF-1024__hash_4096.json` |
| `MOZI-384-XOF-1024` | timing hash_512 | `records/hash-20/MOZI-384-XOF-1024__hash_512.json` |
| `MOZI-384-XOF-1024` | timing hash_65536 | `records/hash-20/MOZI-384-XOF-1024__hash_65536.json` |
| `MOZI-384-XOF-1024` | timing hash_8192 | `records/hash-20/MOZI-384-XOF-1024__hash_8192.json` |
| `MOZI-384-XOF-2048` | KAT log (sha256 `45d335c7cca55490…`) | `kat/hash-20/MOZI-384-XOF-2048.log` |
| `MOZI-384-XOF-2048` | timing hash_1024 | `records/hash-20/MOZI-384-XOF-2048__hash_1024.json` |
| `MOZI-384-XOF-2048` | timing hash_128 | `records/hash-20/MOZI-384-XOF-2048__hash_128.json` |
| `MOZI-384-XOF-2048` | timing hash_16384 | `records/hash-20/MOZI-384-XOF-2048__hash_16384.json` |
| `MOZI-384-XOF-2048` | timing hash_32 | `records/hash-20/MOZI-384-XOF-2048__hash_32.json` |
| `MOZI-384-XOF-2048` | timing hash_4096 | `records/hash-20/MOZI-384-XOF-2048__hash_4096.json` |
| `MOZI-384-XOF-2048` | timing hash_512 | `records/hash-20/MOZI-384-XOF-2048__hash_512.json` |
| `MOZI-384-XOF-2048` | timing hash_65536 | `records/hash-20/MOZI-384-XOF-2048__hash_65536.json` |
| `MOZI-384-XOF-2048` | timing hash_8192 | `records/hash-20/MOZI-384-XOF-2048__hash_8192.json` |
| `MOZI-512` | KAT log (sha256 `d61ee97537d1ce96…`) | `kat/hash-20/MOZI-512.log` |
| `MOZI-512` | timing hash_1024 | `records/hash-20/MOZI-512__hash_1024.json` |
| `MOZI-512` | timing hash_128 | `records/hash-20/MOZI-512__hash_128.json` |
| `MOZI-512` | timing hash_16384 | `records/hash-20/MOZI-512__hash_16384.json` |
| `MOZI-512` | timing hash_32 | `records/hash-20/MOZI-512__hash_32.json` |
| `MOZI-512` | timing hash_4096 | `records/hash-20/MOZI-512__hash_4096.json` |
| `MOZI-512` | timing hash_512 | `records/hash-20/MOZI-512__hash_512.json` |
| `MOZI-512` | timing hash_65536 | `records/hash-20/MOZI-512__hash_65536.json` |
| `MOZI-512` | timing hash_8192 | `records/hash-20/MOZI-512__hash_8192.json` |
| `MOZI-512-XOF-256` | KAT log (sha256 `be0d7624b536189c…`) | `kat/hash-20/MOZI-512-XOF-256.log` |
| `MOZI-512-XOF-256` | timing hash_1024 | `records/hash-20/MOZI-512-XOF-256__hash_1024.json` |
| `MOZI-512-XOF-256` | timing hash_128 | `records/hash-20/MOZI-512-XOF-256__hash_128.json` |
| `MOZI-512-XOF-256` | timing hash_16384 | `records/hash-20/MOZI-512-XOF-256__hash_16384.json` |
| `MOZI-512-XOF-256` | timing hash_32 | `records/hash-20/MOZI-512-XOF-256__hash_32.json` |
| `MOZI-512-XOF-256` | timing hash_4096 | `records/hash-20/MOZI-512-XOF-256__hash_4096.json` |
| `MOZI-512-XOF-256` | timing hash_512 | `records/hash-20/MOZI-512-XOF-256__hash_512.json` |
| `MOZI-512-XOF-256` | timing hash_65536 | `records/hash-20/MOZI-512-XOF-256__hash_65536.json` |
| `MOZI-512-XOF-256` | timing hash_8192 | `records/hash-20/MOZI-512-XOF-256__hash_8192.json` |
| `MOZI-512-XOF-1024` | KAT log (sha256 `2e3a7c7edd4ff058…`) | `kat/hash-20/MOZI-512-XOF-1024.log` |
| `MOZI-512-XOF-1024` | timing hash_1024 | `records/hash-20/MOZI-512-XOF-1024__hash_1024.json` |
| `MOZI-512-XOF-1024` | timing hash_128 | `records/hash-20/MOZI-512-XOF-1024__hash_128.json` |
| `MOZI-512-XOF-1024` | timing hash_16384 | `records/hash-20/MOZI-512-XOF-1024__hash_16384.json` |
| `MOZI-512-XOF-1024` | timing hash_32 | `records/hash-20/MOZI-512-XOF-1024__hash_32.json` |
| `MOZI-512-XOF-1024` | timing hash_4096 | `records/hash-20/MOZI-512-XOF-1024__hash_4096.json` |
| `MOZI-512-XOF-1024` | timing hash_512 | `records/hash-20/MOZI-512-XOF-1024__hash_512.json` |
| `MOZI-512-XOF-1024` | timing hash_65536 | `records/hash-20/MOZI-512-XOF-1024__hash_65536.json` |
| `MOZI-512-XOF-1024` | timing hash_8192 | `records/hash-20/MOZI-512-XOF-1024__hash_8192.json` |
| `MOZI-512-XOF-2048` | KAT log (sha256 `69769b54a0628a1c…`) | `kat/hash-20/MOZI-512-XOF-2048.log` |
| `MOZI-512-XOF-2048` | timing hash_1024 | `records/hash-20/MOZI-512-XOF-2048__hash_1024.json` |
| `MOZI-512-XOF-2048` | timing hash_128 | `records/hash-20/MOZI-512-XOF-2048__hash_128.json` |
| `MOZI-512-XOF-2048` | timing hash_16384 | `records/hash-20/MOZI-512-XOF-2048__hash_16384.json` |
| `MOZI-512-XOF-2048` | timing hash_32 | `records/hash-20/MOZI-512-XOF-2048__hash_32.json` |
| `MOZI-512-XOF-2048` | timing hash_4096 | `records/hash-20/MOZI-512-XOF-2048__hash_4096.json` |
| `MOZI-512-XOF-2048` | timing hash_512 | `records/hash-20/MOZI-512-XOF-2048__hash_512.json` |
| `MOZI-512-XOF-2048` | timing hash_65536 | `records/hash-20/MOZI-512-XOF-2048__hash_65536.json` |
| `MOZI-512-XOF-2048` | timing hash_8192 | `records/hash-20/MOZI-512-XOF-2048__hash_8192.json` |
| `MOZI-768` | KAT log (sha256 `fffdf6ea0dfc33dc…`) | `kat/hash-20/MOZI-768.log` |
| `MOZI-768` | timing hash_1024 | `records/hash-20/MOZI-768__hash_1024.json` |
| `MOZI-768` | timing hash_128 | `records/hash-20/MOZI-768__hash_128.json` |
| `MOZI-768` | timing hash_16384 | `records/hash-20/MOZI-768__hash_16384.json` |
| `MOZI-768` | timing hash_32 | `records/hash-20/MOZI-768__hash_32.json` |
| `MOZI-768` | timing hash_4096 | `records/hash-20/MOZI-768__hash_4096.json` |
| `MOZI-768` | timing hash_512 | `records/hash-20/MOZI-768__hash_512.json` |
| `MOZI-768` | timing hash_65536 | `records/hash-20/MOZI-768__hash_65536.json` |
| `MOZI-768` | timing hash_8192 | `records/hash-20/MOZI-768__hash_8192.json` |
| `MOZI-1024` | KAT log (sha256 `8ee90ea4756694fe…`) | `kat/hash-20/MOZI-1024.log` |
| `MOZI-1024` | timing hash_1024 | `records/hash-20/MOZI-1024__hash_1024.json` |
| `MOZI-1024` | timing hash_128 | `records/hash-20/MOZI-1024__hash_128.json` |
| `MOZI-1024` | timing hash_16384 | `records/hash-20/MOZI-1024__hash_16384.json` |
| `MOZI-1024` | timing hash_32 | `records/hash-20/MOZI-1024__hash_32.json` |
| `MOZI-1024` | timing hash_4096 | `records/hash-20/MOZI-1024__hash_4096.json` |
| `MOZI-1024` | timing hash_512 | `records/hash-20/MOZI-1024__hash_512.json` |
| `MOZI-1024` | timing hash_65536 | `records/hash-20/MOZI-1024__hash_65536.json` |
| `MOZI-1024` | timing hash_8192 | `records/hash-20/MOZI-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

