<!-- synchronized from harness: hash-25/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-25</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101536036577955840.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-25.md">arm_1</a></p>

# hash-25 TaiChi — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: TaiChi
- Implementation versions measured: reference
- Parameter sets: `TaiChi-512`, `TaiChi-768`, `TaiChi-1024`
- Security evaluation: [hash-25 report](../../reports/hash-25.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-25/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `TaiChi-512` | guide | PASS |
| `TaiChi-768` | guide | PASS |
| `TaiChi-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `TaiChi-512` | 32 B | 23.7 k | 741.4 | 11.3 µs | 2.8 | 100000 (5 × 20000) |
| `TaiChi-512` | 128 B | 22.2 k | 173.6 | 10.6 µs | 12.1 | 100000 (5 × 20000) |
| `TaiChi-512` | 512 B | 64.3 k | 125.5 | 30.7 µs | 16.7 | 100000 (5 × 20000) |
| `TaiChi-512` | 1024 B | 128.4 k | 125.4 | 61.3 µs | 16.7 | 61150 (5 × 12230) |
| `TaiChi-512` | 4096 B | 513.0 k | 125.2 | 245 µs | 16.7 | 18850 (5 × 3770) |
| `TaiChi-512` | 8192 B | 1.00 M | 122.3 | 479 µs | 17.1 | 10010 (5 × 2002) |
| `TaiChi-512` | 16384 B | 2.00 M | 122.3 | 957 µs | 17.1 | 5090 (5 × 1018) |
| `TaiChi-512` | 65536 B | 7.95 M | 121.3 | 3.8 ms | 17.3 | 1295 (5 × 259) |
| `TaiChi-768` | 32 B | 23.1 k | 722.9 | 11.1 µs | 2.9 | 100000 (5 × 20000) |
| `TaiChi-768` | 128 B | 21.7 k | 169.8 | 10.4 µs | 12.3 | 100000 (5 × 20000) |
| `TaiChi-768` | 512 B | 86.3 k | 168.6 | 41.2 µs | 12.4 | 81585 (5 × 16317) |
| `TaiChi-768` | 1024 B | 172.3 k | 168.3 | 82.3 µs | 12.4 | 48660 (5 × 9732) |
| `TaiChi-768` | 4096 B | 618.9 k | 151.1 | 296 µs | 13.9 | 15815 (5 × 3163) |
| `TaiChi-768` | 8192 B | 1.21 M | 148.1 | 580 µs | 14.1 | 7450 (5 × 1490) |
| `TaiChi-768` | 16384 B | 2.43 M | 148.1 | 1.16 ms | 14.1 | 4205 (5 × 841) |
| `TaiChi-768` | 65536 B | 9.71 M | 148.1 | 4.64 ms | 14.1 | 1055 (5 × 211) |
| `TaiChi-1024` | 32 B | 44.2 k | 1382.4 | 21.2 µs | 1.5 | 100000 (5 × 20000) |
| `TaiChi-1024` | 128 B | 65.8 k | 514.3 | 31.5 µs | 4.1 | 100000 (5 × 20000) |
| `TaiChi-1024` | 512 B | 129.1 k | 252.1 | 61.8 µs | 8.3 | 63300 (5 × 12660) |
| `TaiChi-1024` | 1024 B | 236.5 k | 230.9 | 113 µs | 9.0 | 37720 (5 × 7544) |
| `TaiChi-1024` | 4096 B | 811.7 k | 198.2 | 389 µs | 10.5 | 12310 (5 × 2462) |
| `TaiChi-1024` | 8192 B | 1.60 M | 195.6 | 768 µs | 10.7 | 6375 (5 × 1275) |
| `TaiChi-1024` | 16384 B | 3.16 M | 192.8 | 1.51 ms | 10.8 | 3235 (5 × 647) |
| `TaiChi-1024` | 65536 B | 12.54 M | 191.4 | 6.01 ms | 10.9 | 820 (5 × 164) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `TaiChi-512` | hash_32 | 14089 | 1684 KiB | 1772 KiB |
| `TaiChi-512` | hash_128 | 14089 | 1664 KiB | 1772 KiB |
| `TaiChi-512` | hash_512 | 14089 | 1668 KiB | 1732 KiB |
| `TaiChi-512` | hash_1024 | 14089 | 1684 KiB | 1760 KiB |
| `TaiChi-512` | hash_4096 | 14089 | 1684 KiB | 1752 KiB |
| `TaiChi-512` | hash_8192 | 14089 | 1676 KiB | 1748 KiB |
| `TaiChi-512` | hash_16384 | 14089 | 1688 KiB | 1788 KiB |
| `TaiChi-512` | hash_65536 | 14089 | 1736 KiB | 1904 KiB |
| `TaiChi-768` | hash_32 | 14089 | 1680 KiB | 1744 KiB |
| `TaiChi-768` | hash_128 | 14089 | 1688 KiB | 1764 KiB |
| `TaiChi-768` | hash_512 | 14089 | 1664 KiB | 1728 KiB |
| `TaiChi-768` | hash_1024 | 14089 | 1684 KiB | 1764 KiB |
| `TaiChi-768` | hash_4096 | 14089 | 1668 KiB | 1788 KiB |
| `TaiChi-768` | hash_8192 | 14089 | 1700 KiB | 1788 KiB |
| `TaiChi-768` | hash_16384 | 14089 | 1680 KiB | 1808 KiB |
| `TaiChi-768` | hash_65536 | 14089 | 1732 KiB | 1884 KiB |
| `TaiChi-1024` | hash_32 | 14073 | 1664 KiB | 4268 KiB |
| `TaiChi-1024` | hash_128 | 14073 | 1672 KiB | 6456 KiB |
| `TaiChi-1024` | hash_512 | 14073 | 1640 KiB | 8892 KiB |
| `TaiChi-1024` | hash_1024 | 14073 | 1680 KiB | 10144 KiB |
| `TaiChi-1024` | hash_4096 | 14073 | 1688 KiB | 11792 KiB |
| `TaiChi-1024` | hash_8192 | 14073 | 1636 KiB | 12128 KiB |
| `TaiChi-1024` | hash_16384 | 14073 | 1644 KiB | 12232 KiB |
| `TaiChi-1024` | hash_65536 | 14073 | 1740 KiB | 12512 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `TaiChi-512` | KAT log (sha256 `81d7575825cc961b…`) | `kat/hash-25/TaiChi-512.log` |
| `TaiChi-512` | timing hash_1024 | `records/hash-25/TaiChi-512__hash_1024.json` |
| `TaiChi-512` | timing hash_128 | `records/hash-25/TaiChi-512__hash_128.json` |
| `TaiChi-512` | timing hash_16384 | `records/hash-25/TaiChi-512__hash_16384.json` |
| `TaiChi-512` | timing hash_32 | `records/hash-25/TaiChi-512__hash_32.json` |
| `TaiChi-512` | timing hash_4096 | `records/hash-25/TaiChi-512__hash_4096.json` |
| `TaiChi-512` | timing hash_512 | `records/hash-25/TaiChi-512__hash_512.json` |
| `TaiChi-512` | timing hash_65536 | `records/hash-25/TaiChi-512__hash_65536.json` |
| `TaiChi-512` | timing hash_8192 | `records/hash-25/TaiChi-512__hash_8192.json` |
| `TaiChi-768` | KAT log (sha256 `412d2874e1ec2ec8…`) | `kat/hash-25/TaiChi-768.log` |
| `TaiChi-768` | timing hash_1024 | `records/hash-25/TaiChi-768__hash_1024.json` |
| `TaiChi-768` | timing hash_128 | `records/hash-25/TaiChi-768__hash_128.json` |
| `TaiChi-768` | timing hash_16384 | `records/hash-25/TaiChi-768__hash_16384.json` |
| `TaiChi-768` | timing hash_32 | `records/hash-25/TaiChi-768__hash_32.json` |
| `TaiChi-768` | timing hash_4096 | `records/hash-25/TaiChi-768__hash_4096.json` |
| `TaiChi-768` | timing hash_512 | `records/hash-25/TaiChi-768__hash_512.json` |
| `TaiChi-768` | timing hash_65536 | `records/hash-25/TaiChi-768__hash_65536.json` |
| `TaiChi-768` | timing hash_8192 | `records/hash-25/TaiChi-768__hash_8192.json` |
| `TaiChi-1024` | KAT log (sha256 `31b4d6afe3d0bc71…`) | `kat/hash-25/TaiChi-1024.log` |
| `TaiChi-1024` | timing hash_1024 | `records/hash-25/TaiChi-1024__hash_1024.json` |
| `TaiChi-1024` | timing hash_128 | `records/hash-25/TaiChi-1024__hash_128.json` |
| `TaiChi-1024` | timing hash_16384 | `records/hash-25/TaiChi-1024__hash_16384.json` |
| `TaiChi-1024` | timing hash_32 | `records/hash-25/TaiChi-1024__hash_32.json` |
| `TaiChi-1024` | timing hash_4096 | `records/hash-25/TaiChi-1024__hash_4096.json` |
| `TaiChi-1024` | timing hash_512 | `records/hash-25/TaiChi-1024__hash_512.json` |
| `TaiChi-1024` | timing hash_65536 | `records/hash-25/TaiChi-1024__hash_65536.json` |
| `TaiChi-1024` | timing hash_8192 | `records/hash-25/TaiChi-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

