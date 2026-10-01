<!-- synchronized from harness: hash-33/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-33</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-33.md">arm_1</a></p>

# hash-33 Thunder Hash Family — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Thunder Hash Family
- Implementation versions measured: reference
- Parameter sets: `Thunder-512`, `Thunder-768`, `Thunder-1024`, `Thunder-XOF-256`, `Thunder-XOF-384`, `Thunder-XOF-512`
- Security evaluation: [hash-33 report](../../reports/hash-33.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101533797931110400.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-33/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Thunder-512` | guide | PASS |
| `Thunder-768` | guide | PASS |
| `Thunder-1024` | guide | PASS |
| `Thunder-XOF-256` | guide | PASS |
| `Thunder-XOF-384` | guide | PASS |
| `Thunder-XOF-512` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Thunder-512` | 32 B | 4276 | 133.6 | 2.04 µs | 15.6 | 100000 (5 × 20000) |
| `Thunder-512` | 128 B | 8466 | 66.1 | 4.05 µs | 31.6 | 100000 (5 × 20000) |
| `Thunder-512` | 512 B | 21.0 k | 41.0 | 10 µs | 51.1 | 100000 (5 × 20000) |
| `Thunder-512` | 1024 B | 37.4 k | 36.6 | 17.9 µs | 57.2 | 100000 (5 × 20000) |
| `Thunder-512` | 4096 B | 137.1 k | 33.5 | 65.5 µs | 62.5 | 68670 (5 × 13734) |
| `Thunder-512` | 8192 B | 270.1 k | 33.0 | 129 µs | 63.5 | 36635 (5 × 7327) |
| `Thunder-512` | 16384 B | 536.3 k | 32.7 | 256 µs | 63.9 | 19185 (5 × 3837) |
| `Thunder-512` | 65536 B | 2.13 M | 32.4 | 1.02 ms | 64.6 | 4830 (5 × 966) |
| `Thunder-768` | 32 B | 4240 | 132.5 | 2.03 µs | 15.8 | 100000 (5 × 20000) |
| `Thunder-768` | 128 B | 8426 | 65.8 | 4.03 µs | 31.8 | 100000 (5 × 20000) |
| `Thunder-768` | 512 B | 25.2 k | 49.1 | 12 µs | 42.6 | 100000 (5 × 20000) |
| `Thunder-768` | 1024 B | 45.8 k | 44.7 | 21.9 µs | 46.8 | 100000 (5 × 20000) |
| `Thunder-768` | 4096 B | 178.3 k | 43.5 | 85.2 µs | 48.1 | 53775 (5 × 10755) |
| `Thunder-768` | 8192 B | 357.3 k | 43.6 | 171 µs | 48.0 | 28000 (5 × 5600) |
| `Thunder-768` | 16384 B | 710.5 k | 43.4 | 339 µs | 48.3 | 14395 (5 × 2879) |
| `Thunder-768` | 65536 B | 2.84 M | 43.3 | 1.36 ms | 48.3 | 3600 (5 × 720) |
| `Thunder-1024` | 32 B | 4266 | 133.3 | 2.04 µs | 15.7 | 100000 (5 × 20000) |
| `Thunder-1024` | 128 B | 12.5 k | 97.9 | 6 µs | 21.3 | 100000 (5 × 20000) |
| `Thunder-1024` | 512 B | 37.3 k | 72.9 | 17.8 µs | 28.7 | 100000 (5 × 20000) |
| `Thunder-1024` | 1024 B | 70.3 k | 68.7 | 33.6 µs | 30.5 | 100000 (5 × 20000) |
| `Thunder-1024` | 4096 B | 268.1 k | 65.5 | 128 µs | 32.0 | 36640 (5 × 7328) |
| `Thunder-1024` | 8192 B | 530.3 k | 64.7 | 253 µs | 32.3 | 19020 (5 × 3804) |
| `Thunder-1024` | 16384 B | 1.06 M | 64.8 | 507 µs | 32.3 | 9790 (5 × 1958) |
| `Thunder-1024` | 65536 B | 4.24 M | 64.7 | 2.02 ms | 32.4 | 2450 (5 × 490) |
| `Thunder-XOF-256` | 32 B | 11.4 k | 357.5 | 5.47 µs | 5.9 | 100000 (5 × 20000) |
| `Thunder-XOF-256` | 128 B | 15.6 k | 121.7 | 7.44 µs | 17.2 | 100000 (5 × 20000) |
| `Thunder-XOF-256` | 512 B | 28.1 k | 54.9 | 13.4 µs | 38.2 | 100000 (5 × 20000) |
| `Thunder-XOF-256` | 1024 B | 44.8 k | 43.8 | 21.4 µs | 47.8 | 100000 (5 × 20000) |
| `Thunder-XOF-256` | 4096 B | 144.5 k | 35.3 | 69 µs | 59.3 | 65680 (5 × 13136) |
| `Thunder-XOF-256` | 8192 B | 277.9 k | 33.9 | 133 µs | 61.7 | 36105 (5 × 7221) |
| `Thunder-XOF-256` | 16384 B | 542.6 k | 33.1 | 259 µs | 63.2 | 18725 (5 × 3745) |
| `Thunder-XOF-256` | 65536 B | 2.14 M | 32.7 | 1.02 ms | 64.0 | 4890 (5 × 978) |
| `Thunder-XOF-384` | 32 B | 10.7 k | 334.4 | 5.12 µs | 6.3 | 100000 (5 × 20000) |
| `Thunder-XOF-384` | 128 B | 14.8 k | 115.9 | 7.09 µs | 18.1 | 100000 (5 × 20000) |
| `Thunder-XOF-384` | 512 B | 31.4 k | 61.3 | 15 µs | 34.2 | 100000 (5 × 20000) |
| `Thunder-XOF-384` | 1024 B | 52.2 k | 51.0 | 25 µs | 41.0 | 100000 (5 × 20000) |
| `Thunder-XOF-384` | 4096 B | 185.1 k | 45.2 | 88.4 µs | 46.3 | 52545 (5 × 10509) |
| `Thunder-XOF-384` | 8192 B | 362.3 k | 44.2 | 173 µs | 47.3 | 27725 (5 × 5545) |
| `Thunder-XOF-384` | 16384 B | 716.2 k | 43.7 | 342 µs | 47.9 | 14275 (5 × 2855) |
| `Thunder-XOF-384` | 65536 B | 2.84 M | 43.4 | 1.36 ms | 48.2 | 3695 (5 × 739) |
| `Thunder-XOF-512` | 32 B | 9996 | 312.4 | 4.78 µs | 6.7 | 100000 (5 × 20000) |
| `Thunder-XOF-512` | 128 B | 18.3 k | 143.1 | 8.75 µs | 14.6 | 100000 (5 × 20000) |
| `Thunder-XOF-512` | 512 B | 43.0 k | 84.0 | 20.5 µs | 24.9 | 100000 (5 × 20000) |
| `Thunder-XOF-512` | 1024 B | 76.1 k | 74.3 | 36.4 µs | 28.2 | 100000 (5 × 20000) |
| `Thunder-XOF-512` | 4096 B | 274.7 k | 67.1 | 131 µs | 31.2 | 36545 (5 × 7309) |
| `Thunder-XOF-512` | 8192 B | 539.0 k | 65.8 | 257 µs | 31.8 | 19095 (5 × 3819) |
| `Thunder-XOF-512` | 16384 B | 1.07 M | 65.2 | 510 µs | 32.1 | 8055 (5 × 1611) |
| `Thunder-XOF-512` | 65536 B | 4.22 M | 64.4 | 2.02 ms | 32.5 | 2475 (5 × 495) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Thunder-512` | hash_32 | 12865 | 1692 KiB | 1756 KiB |
| `Thunder-512` | hash_128 | 12865 | 1672 KiB | 1772 KiB |
| `Thunder-512` | hash_512 | 12865 | 1668 KiB | 1732 KiB |
| `Thunder-512` | hash_1024 | 12865 | 1652 KiB | 1776 KiB |
| `Thunder-512` | hash_4096 | 12865 | 1680 KiB | 1780 KiB |
| `Thunder-512` | hash_8192 | 12865 | 1692 KiB | 1784 KiB |
| `Thunder-512` | hash_16384 | 12865 | 1704 KiB | 1792 KiB |
| `Thunder-512` | hash_65536 | 12865 | 1732 KiB | 1796 KiB |
| `Thunder-768` | hash_32 | 12833 | 1656 KiB | 1780 KiB |
| `Thunder-768` | hash_128 | 12833 | 1684 KiB | 1748 KiB |
| `Thunder-768` | hash_512 | 12833 | 1688 KiB | 1752 KiB |
| `Thunder-768` | hash_1024 | 12833 | 1644 KiB | 1772 KiB |
| `Thunder-768` | hash_4096 | 12833 | 1688 KiB | 1760 KiB |
| `Thunder-768` | hash_8192 | 12833 | 1688 KiB | 1752 KiB |
| `Thunder-768` | hash_16384 | 12833 | 1704 KiB | 1776 KiB |
| `Thunder-768` | hash_65536 | 12833 | 1740 KiB | 1836 KiB |
| `Thunder-1024` | hash_32 | 12905 | 1564 KiB | 1688 KiB |
| `Thunder-1024` | hash_128 | 12905 | 1672 KiB | 1756 KiB |
| `Thunder-1024` | hash_512 | 12905 | 1680 KiB | 1756 KiB |
| `Thunder-1024` | hash_1024 | 12905 | 1680 KiB | 1776 KiB |
| `Thunder-1024` | hash_4096 | 12905 | 1660 KiB | 1784 KiB |
| `Thunder-1024` | hash_8192 | 12905 | 1688 KiB | 1752 KiB |
| `Thunder-1024` | hash_16384 | 12905 | 1700 KiB | 1764 KiB |
| `Thunder-1024` | hash_65536 | 12905 | 1728 KiB | 1836 KiB |
| `Thunder-XOF-256` | hash_32 | 13417 | 1668 KiB | 1756 KiB |
| `Thunder-XOF-256` | hash_128 | 13417 | 1688 KiB | 1752 KiB |
| `Thunder-XOF-256` | hash_512 | 13417 | 1672 KiB | 1756 KiB |
| `Thunder-XOF-256` | hash_1024 | 13417 | 1596 KiB | 1724 KiB |
| `Thunder-XOF-256` | hash_4096 | 13417 | 1676 KiB | 1784 KiB |
| `Thunder-XOF-256` | hash_8192 | 13417 | 1680 KiB | 1768 KiB |
| `Thunder-XOF-256` | hash_16384 | 13417 | 1704 KiB | 1784 KiB |
| `Thunder-XOF-256` | hash_65536 | 13417 | 1752 KiB | 1832 KiB |
| `Thunder-XOF-384` | hash_32 | 13321 | 1684 KiB | 1748 KiB |
| `Thunder-XOF-384` | hash_128 | 13321 | 1688 KiB | 1752 KiB |
| `Thunder-XOF-384` | hash_512 | 13321 | 1692 KiB | 1756 KiB |
| `Thunder-XOF-384` | hash_1024 | 13321 | 1676 KiB | 1740 KiB |
| `Thunder-XOF-384` | hash_4096 | 13321 | 1680 KiB | 1744 KiB |
| `Thunder-XOF-384` | hash_8192 | 13321 | 1676 KiB | 1740 KiB |
| `Thunder-XOF-384` | hash_16384 | 13321 | 1676 KiB | 1788 KiB |
| `Thunder-XOF-384` | hash_65536 | 13321 | 1732 KiB | 1832 KiB |
| `Thunder-XOF-512` | hash_32 | 13361 | 1672 KiB | 1736 KiB |
| `Thunder-XOF-512` | hash_128 | 13361 | 1688 KiB | 1752 KiB |
| `Thunder-XOF-512` | hash_512 | 13361 | 1680 KiB | 1744 KiB |
| `Thunder-XOF-512` | hash_1024 | 13361 | 1684 KiB | 1780 KiB |
| `Thunder-XOF-512` | hash_4096 | 13361 | 1668 KiB | 1776 KiB |
| `Thunder-XOF-512` | hash_8192 | 13361 | 1680 KiB | 1780 KiB |
| `Thunder-XOF-512` | hash_16384 | 13361 | 1684 KiB | 1796 KiB |
| `Thunder-XOF-512` | hash_65536 | 13361 | 1732 KiB | 1832 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Thunder-512` | KAT log (sha256 `63a5e003891282f1…`) | `kat/hash-33/Thunder-512.log` |
| `Thunder-512` | timing hash_1024 | `records/hash-33/Thunder-512__hash_1024.json` |
| `Thunder-512` | timing hash_128 | `records/hash-33/Thunder-512__hash_128.json` |
| `Thunder-512` | timing hash_16384 | `records/hash-33/Thunder-512__hash_16384.json` |
| `Thunder-512` | timing hash_32 | `records/hash-33/Thunder-512__hash_32.json` |
| `Thunder-512` | timing hash_4096 | `records/hash-33/Thunder-512__hash_4096.json` |
| `Thunder-512` | timing hash_512 | `records/hash-33/Thunder-512__hash_512.json` |
| `Thunder-512` | timing hash_65536 | `records/hash-33/Thunder-512__hash_65536.json` |
| `Thunder-512` | timing hash_8192 | `records/hash-33/Thunder-512__hash_8192.json` |
| `Thunder-768` | KAT log (sha256 `286f125d564d791b…`) | `kat/hash-33/Thunder-768.log` |
| `Thunder-768` | timing hash_1024 | `records/hash-33/Thunder-768__hash_1024.json` |
| `Thunder-768` | timing hash_128 | `records/hash-33/Thunder-768__hash_128.json` |
| `Thunder-768` | timing hash_16384 | `records/hash-33/Thunder-768__hash_16384.json` |
| `Thunder-768` | timing hash_32 | `records/hash-33/Thunder-768__hash_32.json` |
| `Thunder-768` | timing hash_4096 | `records/hash-33/Thunder-768__hash_4096.json` |
| `Thunder-768` | timing hash_512 | `records/hash-33/Thunder-768__hash_512.json` |
| `Thunder-768` | timing hash_65536 | `records/hash-33/Thunder-768__hash_65536.json` |
| `Thunder-768` | timing hash_8192 | `records/hash-33/Thunder-768__hash_8192.json` |
| `Thunder-1024` | KAT log (sha256 `4566b268acd93efc…`) | `kat/hash-33/Thunder-1024.log` |
| `Thunder-1024` | timing hash_1024 | `records/hash-33/Thunder-1024__hash_1024.json` |
| `Thunder-1024` | timing hash_128 | `records/hash-33/Thunder-1024__hash_128.json` |
| `Thunder-1024` | timing hash_16384 | `records/hash-33/Thunder-1024__hash_16384.json` |
| `Thunder-1024` | timing hash_32 | `records/hash-33/Thunder-1024__hash_32.json` |
| `Thunder-1024` | timing hash_4096 | `records/hash-33/Thunder-1024__hash_4096.json` |
| `Thunder-1024` | timing hash_512 | `records/hash-33/Thunder-1024__hash_512.json` |
| `Thunder-1024` | timing hash_65536 | `records/hash-33/Thunder-1024__hash_65536.json` |
| `Thunder-1024` | timing hash_8192 | `records/hash-33/Thunder-1024__hash_8192.json` |
| `Thunder-XOF-256` | KAT log (sha256 `7c96672deb6f2e19…`) | `kat/hash-33/Thunder-XOF-256.log` |
| `Thunder-XOF-256` | timing hash_1024 | `records/hash-33/Thunder-XOF-256__hash_1024.json` |
| `Thunder-XOF-256` | timing hash_128 | `records/hash-33/Thunder-XOF-256__hash_128.json` |
| `Thunder-XOF-256` | timing hash_16384 | `records/hash-33/Thunder-XOF-256__hash_16384.json` |
| `Thunder-XOF-256` | timing hash_32 | `records/hash-33/Thunder-XOF-256__hash_32.json` |
| `Thunder-XOF-256` | timing hash_4096 | `records/hash-33/Thunder-XOF-256__hash_4096.json` |
| `Thunder-XOF-256` | timing hash_512 | `records/hash-33/Thunder-XOF-256__hash_512.json` |
| `Thunder-XOF-256` | timing hash_65536 | `records/hash-33/Thunder-XOF-256__hash_65536.json` |
| `Thunder-XOF-256` | timing hash_8192 | `records/hash-33/Thunder-XOF-256__hash_8192.json` |
| `Thunder-XOF-384` | KAT log (sha256 `23c62d42218b7f0b…`) | `kat/hash-33/Thunder-XOF-384.log` |
| `Thunder-XOF-384` | timing hash_1024 | `records/hash-33/Thunder-XOF-384__hash_1024.json` |
| `Thunder-XOF-384` | timing hash_128 | `records/hash-33/Thunder-XOF-384__hash_128.json` |
| `Thunder-XOF-384` | timing hash_16384 | `records/hash-33/Thunder-XOF-384__hash_16384.json` |
| `Thunder-XOF-384` | timing hash_32 | `records/hash-33/Thunder-XOF-384__hash_32.json` |
| `Thunder-XOF-384` | timing hash_4096 | `records/hash-33/Thunder-XOF-384__hash_4096.json` |
| `Thunder-XOF-384` | timing hash_512 | `records/hash-33/Thunder-XOF-384__hash_512.json` |
| `Thunder-XOF-384` | timing hash_65536 | `records/hash-33/Thunder-XOF-384__hash_65536.json` |
| `Thunder-XOF-384` | timing hash_8192 | `records/hash-33/Thunder-XOF-384__hash_8192.json` |
| `Thunder-XOF-512` | KAT log (sha256 `ff24b90cbc52acd9…`) | `kat/hash-33/Thunder-XOF-512.log` |
| `Thunder-XOF-512` | timing hash_1024 | `records/hash-33/Thunder-XOF-512__hash_1024.json` |
| `Thunder-XOF-512` | timing hash_128 | `records/hash-33/Thunder-XOF-512__hash_128.json` |
| `Thunder-XOF-512` | timing hash_16384 | `records/hash-33/Thunder-XOF-512__hash_16384.json` |
| `Thunder-XOF-512` | timing hash_32 | `records/hash-33/Thunder-XOF-512__hash_32.json` |
| `Thunder-XOF-512` | timing hash_4096 | `records/hash-33/Thunder-XOF-512__hash_4096.json` |
| `Thunder-XOF-512` | timing hash_512 | `records/hash-33/Thunder-XOF-512__hash_512.json` |
| `Thunder-XOF-512` | timing hash_65536 | `records/hash-33/Thunder-XOF-512__hash_65536.json` |
| `Thunder-XOF-512` | timing hash_8192 | `records/hash-33/Thunder-XOF-512__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

