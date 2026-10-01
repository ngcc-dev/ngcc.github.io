<!-- synchronized from harness: hash-34/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-34</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-34.md">arm_1</a></p>

# hash-34 WChain Hash Function — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: WChain Hash Function
- Implementation versions measured: reference
- Parameter sets: `WChain-V1-512`, `WChain-V2-1024`
- Security evaluation: [hash-34 report](../../reports/hash-34.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101533578757754880.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-34/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `WChain-V1-512` | guide | PASS |
| `WChain-V2-1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `WChain-V1-512` | 32 B | 2099 | 65.6 | 1 µs | 31.9 | 100000 (5 × 20000) |
| `WChain-V1-512` | 128 B | 2060 | 16.1 | 987 ns | 129.7 | 100000 (5 × 20000) |
| `WChain-V1-512` | 512 B | 5015 | 9.8 | 2.4 µs | 213.5 | 100000 (5 × 20000) |
| `WChain-V1-512` | 1024 B | 8844 | 8.6 | 4.23 µs | 242.1 | 100000 (5 × 20000) |
| `WChain-V1-512` | 4096 B | 29.2 k | 7.1 | 13.9 µs | 293.6 | 100000 (5 × 20000) |
| `WChain-V1-512` | 8192 B | 56.1 k | 6.8 | 26.8 µs | 305.9 | 100000 (5 × 20000) |
| `WChain-V1-512` | 16384 B | 110.3 k | 6.7 | 52.7 µs | 310.8 | 87225 (5 × 17445) |
| `WChain-V1-512` | 65536 B | 433.6 k | 6.6 | 207 µs | 316.4 | 21485 (5 × 4297) |
| `WChain-V2-1024` | 32 B | 6691 | 209.1 | 3.2 µs | 10.0 | 100000 (5 × 20000) |
| `WChain-V2-1024` | 128 B | 6696 | 52.3 | 3.2 µs | 40.0 | 100000 (5 × 20000) |
| `WChain-V2-1024` | 512 B | 9967 | 19.5 | 4.76 µs | 107.5 | 100000 (5 × 20000) |
| `WChain-V2-1024` | 1024 B | 16.5 k | 16.1 | 7.89 µs | 129.9 | 100000 (5 × 20000) |
| `WChain-V2-1024` | 4096 B | 52.3 k | 12.8 | 25 µs | 164.1 | 100000 (5 × 20000) |
| `WChain-V2-1024` | 8192 B | 97.7 k | 11.9 | 46.7 µs | 175.5 | 91665 (5 × 18333) |
| `WChain-V2-1024` | 16384 B | 188.8 k | 11.5 | 90.2 µs | 181.6 | 51015 (5 × 10203) |
| `WChain-V2-1024` | 65536 B | 746.0 k | 11.4 | 356 µs | 183.9 | 13720 (5 × 2744) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `WChain-V1-512` | hash_32 | 21173 | 1688 KiB | 1788 KiB |
| `WChain-V1-512` | hash_128 | 21173 | 1700 KiB | 1764 KiB |
| `WChain-V1-512` | hash_512 | 21173 | 1676 KiB | 1784 KiB |
| `WChain-V1-512` | hash_1024 | 21173 | 1704 KiB | 1788 KiB |
| `WChain-V1-512` | hash_4096 | 21173 | 1692 KiB | 1756 KiB |
| `WChain-V1-512` | hash_8192 | 21173 | 1704 KiB | 1792 KiB |
| `WChain-V1-512` | hash_16384 | 21173 | 1716 KiB | 1788 KiB |
| `WChain-V1-512` | hash_65536 | 21173 | 1752 KiB | 1832 KiB |
| `WChain-V2-1024` | hash_32 | 21173 | 1696 KiB | 1784 KiB |
| `WChain-V2-1024` | hash_128 | 21173 | 1684 KiB | 1748 KiB |
| `WChain-V2-1024` | hash_512 | 21173 | 1676 KiB | 1768 KiB |
| `WChain-V2-1024` | hash_1024 | 21173 | 1688 KiB | 1784 KiB |
| `WChain-V2-1024` | hash_4096 | 21173 | 1668 KiB | 1792 KiB |
| `WChain-V2-1024` | hash_8192 | 21173 | 1684 KiB | 1784 KiB |
| `WChain-V2-1024` | hash_16384 | 21173 | 1704 KiB | 1796 KiB |
| `WChain-V2-1024` | hash_65536 | 21173 | 1736 KiB | 1804 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `WChain-V1-512` | KAT log (sha256 `e97e84bbe8988f52…`) | `kat/hash-34/WChain-V1-512.log` |
| `WChain-V1-512` | timing hash_1024 | `records/hash-34/WChain-V1-512__hash_1024.json` |
| `WChain-V1-512` | timing hash_128 | `records/hash-34/WChain-V1-512__hash_128.json` |
| `WChain-V1-512` | timing hash_16384 | `records/hash-34/WChain-V1-512__hash_16384.json` |
| `WChain-V1-512` | timing hash_32 | `records/hash-34/WChain-V1-512__hash_32.json` |
| `WChain-V1-512` | timing hash_4096 | `records/hash-34/WChain-V1-512__hash_4096.json` |
| `WChain-V1-512` | timing hash_512 | `records/hash-34/WChain-V1-512__hash_512.json` |
| `WChain-V1-512` | timing hash_65536 | `records/hash-34/WChain-V1-512__hash_65536.json` |
| `WChain-V1-512` | timing hash_8192 | `records/hash-34/WChain-V1-512__hash_8192.json` |
| `WChain-V2-1024` | KAT log (sha256 `234d85c56e56e60a…`) | `kat/hash-34/WChain-V2-1024.log` |
| `WChain-V2-1024` | timing hash_1024 | `records/hash-34/WChain-V2-1024__hash_1024.json` |
| `WChain-V2-1024` | timing hash_128 | `records/hash-34/WChain-V2-1024__hash_128.json` |
| `WChain-V2-1024` | timing hash_16384 | `records/hash-34/WChain-V2-1024__hash_16384.json` |
| `WChain-V2-1024` | timing hash_32 | `records/hash-34/WChain-V2-1024__hash_32.json` |
| `WChain-V2-1024` | timing hash_4096 | `records/hash-34/WChain-V2-1024__hash_4096.json` |
| `WChain-V2-1024` | timing hash_512 | `records/hash-34/WChain-V2-1024__hash_512.json` |
| `WChain-V2-1024` | timing hash_65536 | `records/hash-34/WChain-V2-1024__hash_65536.json` |
| `WChain-V2-1024` | timing hash_8192 | `records/hash-34/WChain-V2-1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

