<!-- synchronized from harness: hash-02/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-02</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-02.md">arm_1</a></p>

# hash-02 AXIS: Advanced eXpandable Iterative Stream-based Hash — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: AXIS: Advanced eXpandable Iterative Stream-based Hash
- Implementation versions measured: reference
- Parameter sets: `AXIS-512`, `AXIS-768`, `AXIS-1024`
- Security evaluation: [hash-02 report](../../reports/hash-02.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101540899009417216.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-02/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `AXIS-512` | guide | PASS |
| `AXIS-768` | guide | PASS |
| `AXIS-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `AXIS-512` | 32 B | 58.7 k | 1833.3 | 28 µs | 1.1 | 100000 (5 × 20000) |
| `AXIS-512` | 128 B | 62.0 k | 484.5 | 29.6 µs | 4.3 | 100000 (5 × 20000) |
| `AXIS-512` | 512 B | 76.1 k | 148.7 | 36.4 µs | 14.1 | 100000 (5 × 20000) |
| `AXIS-512` | 1024 B | 94.8 k | 92.6 | 45.3 µs | 22.6 | 93735 (5 × 18747) |
| `AXIS-512` | 4096 B | 206.3 k | 50.4 | 98.6 µs | 41.6 | 43505 (5 × 8701) |
| `AXIS-512` | 8192 B | 355.4 k | 43.4 | 170 µs | 48.3 | 28165 (5 × 5633) |
| `AXIS-512` | 16384 B | 654.4 k | 39.9 | 313 µs | 52.4 | 15750 (5 × 3150) |
| `AXIS-512` | 65536 B | 2.45 M | 37.4 | 1.17 ms | 56.0 | 4255 (5 × 851) |
| `AXIS-768` | 32 B | 72.6 k | 2269.0 | 34.7 µs | 0.9 | 100000 (5 × 20000) |
| `AXIS-768` | 128 B | 81.8 k | 639.1 | 39.1 µs | 3.3 | 95435 (5 × 19087) |
| `AXIS-768` | 512 B | 119.4 k | 233.1 | 57 µs | 9.0 | 76270 (5 × 15254) |
| `AXIS-768` | 1024 B | 169.3 k | 165.4 | 80.9 µs | 12.7 | 58055 (5 × 11611) |
| `AXIS-768` | 4096 B | 466.5 k | 113.9 | 223 µs | 18.4 | 24655 (5 × 4931) |
| `AXIS-768` | 8192 B | 840.4 k | 102.6 | 401 µs | 20.4 | 14110 (5 × 2822) |
| `AXIS-768` | 16384 B | 1.63 M | 99.7 | 781 µs | 21.0 | 7455 (5 × 1491) |
| `AXIS-768` | 65536 B | 5.96 M | 91.0 | 2.85 ms | 23.0 | 1995 (5 × 399) |
| `AXIS-1024` | 32 B | 96.3 k | 3009.6 | 46 µs | 0.7 | 80460 (5 × 16092) |
| `AXIS-1024` | 128 B | 102.9 k | 804.0 | 49.2 µs | 2.6 | 79430 (5 × 15886) |
| `AXIS-1024` | 512 B | 126.3 k | 246.7 | 60.3 µs | 8.5 | 67480 (5 × 13496) |
| `AXIS-1024` | 1024 B | 155.5 k | 151.9 | 74.3 µs | 13.8 | 56330 (5 × 11266) |
| `AXIS-1024` | 4096 B | 332.5 k | 81.2 | 159 µs | 25.8 | 29085 (5 × 5817) |
| `AXIS-1024` | 8192 B | 569.3 k | 69.5 | 272 µs | 30.1 | 17420 (5 × 3484) |
| `AXIS-1024` | 16384 B | 1.04 M | 63.5 | 497 µs | 33.0 | 9840 (5 × 1968) |
| `AXIS-1024` | 65536 B | 3.88 M | 59.1 | 1.85 ms | 35.4 | 2675 (5 × 535) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `AXIS-512` | hash_32 | 44217 | 1700 KiB | 1792 KiB |
| `AXIS-512` | hash_128 | 44217 | 1712 KiB | 1780 KiB |
| `AXIS-512` | hash_512 | 44217 | 1700 KiB | 1764 KiB |
| `AXIS-512` | hash_1024 | 44217 | 1712 KiB | 1808 KiB |
| `AXIS-512` | hash_4096 | 44217 | 1720 KiB | 1808 KiB |
| `AXIS-512` | hash_8192 | 44217 | 1716 KiB | 1816 KiB |
| `AXIS-512` | hash_16384 | 44217 | 1740 KiB | 1816 KiB |
| `AXIS-512` | hash_65536 | 44217 | 1760 KiB | 1872 KiB |
| `AXIS-768` | hash_32 | 44217 | 1712 KiB | 1808 KiB |
| `AXIS-768` | hash_128 | 44217 | 1724 KiB | 1788 KiB |
| `AXIS-768` | hash_512 | 44217 | 1696 KiB | 1800 KiB |
| `AXIS-768` | hash_1024 | 44217 | 1704 KiB | 1804 KiB |
| `AXIS-768` | hash_4096 | 44217 | 1708 KiB | 1800 KiB |
| `AXIS-768` | hash_8192 | 44217 | 1728 KiB | 1796 KiB |
| `AXIS-768` | hash_16384 | 44217 | 1736 KiB | 1800 KiB |
| `AXIS-768` | hash_65536 | 44217 | 1780 KiB | 1872 KiB |
| `AXIS-1024` | hash_32 | 44217 | 1724 KiB | 1792 KiB |
| `AXIS-1024` | hash_128 | 44217 | 1720 KiB | 1784 KiB |
| `AXIS-1024` | hash_512 | 44217 | 1708 KiB | 1800 KiB |
| `AXIS-1024` | hash_1024 | 44217 | 1712 KiB | 1808 KiB |
| `AXIS-1024` | hash_4096 | 44217 | 1704 KiB | 1796 KiB |
| `AXIS-1024` | hash_8192 | 44217 | 1732 KiB | 1816 KiB |
| `AXIS-1024` | hash_16384 | 44217 | 1708 KiB | 1772 KiB |
| `AXIS-1024` | hash_65536 | 44217 | 1736 KiB | 1864 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `AXIS-512` | KAT log (sha256 `f25421f8151e1d59…`) | `kat/hash-02/AXIS-512.log` |
| `AXIS-512` | timing hash_1024 | `records/hash-02/AXIS-512__hash_1024.json` |
| `AXIS-512` | timing hash_128 | `records/hash-02/AXIS-512__hash_128.json` |
| `AXIS-512` | timing hash_16384 | `records/hash-02/AXIS-512__hash_16384.json` |
| `AXIS-512` | timing hash_32 | `records/hash-02/AXIS-512__hash_32.json` |
| `AXIS-512` | timing hash_4096 | `records/hash-02/AXIS-512__hash_4096.json` |
| `AXIS-512` | timing hash_512 | `records/hash-02/AXIS-512__hash_512.json` |
| `AXIS-512` | timing hash_65536 | `records/hash-02/AXIS-512__hash_65536.json` |
| `AXIS-512` | timing hash_8192 | `records/hash-02/AXIS-512__hash_8192.json` |
| `AXIS-768` | KAT log (sha256 `6c6cc30153809afd…`) | `kat/hash-02/AXIS-768.log` |
| `AXIS-768` | timing hash_1024 | `records/hash-02/AXIS-768__hash_1024.json` |
| `AXIS-768` | timing hash_128 | `records/hash-02/AXIS-768__hash_128.json` |
| `AXIS-768` | timing hash_16384 | `records/hash-02/AXIS-768__hash_16384.json` |
| `AXIS-768` | timing hash_32 | `records/hash-02/AXIS-768__hash_32.json` |
| `AXIS-768` | timing hash_4096 | `records/hash-02/AXIS-768__hash_4096.json` |
| `AXIS-768` | timing hash_512 | `records/hash-02/AXIS-768__hash_512.json` |
| `AXIS-768` | timing hash_65536 | `records/hash-02/AXIS-768__hash_65536.json` |
| `AXIS-768` | timing hash_8192 | `records/hash-02/AXIS-768__hash_8192.json` |
| `AXIS-1024` | KAT log (sha256 `b1193b28e03eb3ab…`) | `kat/hash-02/AXIS-1024.log` |
| `AXIS-1024` | timing hash_1024 | `records/hash-02/AXIS-1024__hash_1024.json` |
| `AXIS-1024` | timing hash_128 | `records/hash-02/AXIS-1024__hash_128.json` |
| `AXIS-1024` | timing hash_16384 | `records/hash-02/AXIS-1024__hash_16384.json` |
| `AXIS-1024` | timing hash_32 | `records/hash-02/AXIS-1024__hash_32.json` |
| `AXIS-1024` | timing hash_4096 | `records/hash-02/AXIS-1024__hash_4096.json` |
| `AXIS-1024` | timing hash_512 | `records/hash-02/AXIS-1024__hash_512.json` |
| `AXIS-1024` | timing hash_65536 | `records/hash-02/AXIS-1024__hash_65536.json` |
| `AXIS-1024` | timing hash_8192 | `records/hash-02/AXIS-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

