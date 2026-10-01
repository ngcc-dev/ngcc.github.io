<!-- synchronized from harness: hash-35/perf_x86_1.md -->
<p class="crumb"><a href="index.md">Performance x86_1</a> › <code>hash-35</code> · <a href="method.md">method</a> · <a href="https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101533368094642176.html">NICCS page</a> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-35.md">arm_1</a></p>

# hash-35 Wish Hash Function — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Wish Hash Function
- Implementation versions measured: reference
- Parameter sets: `Wish512`, `Wish1024`
- Security evaluation: [hash-35 report](../../reports/hash-35.md)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-35/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `Wish512` | guide | PASS |
| `Wish1024` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `Wish512` | 32 B | 245.8 k | 7680.8 | 117 µs | 0.3 | 32295 (5 × 6459) |
| `Wish512` | 128 B | 890.3 k | 6955.2 | 425 µs | 0.3 | 11020 (5 × 2204) |
| `Wish512` | 512 B | 2.71 M | 5300.6 | 1.3 ms | 0.4 | 3750 (5 × 750) |
| `Wish512` | 1024 B | 5.14 M | 5020.5 | 2.46 ms | 0.4 | 2005 (5 × 401) |
| `Wish512` | 4096 B | 19.73 M | 4815.9 | 9.42 ms | 0.4 | 525 (5 × 105) |
| `Wish512` | 8192 B | 39.17 M | 4781.1 | 18.7 ms | 0.4 | 270 (5 × 54) |
| `Wish512` | 16384 B | 78.09 M | 4766.3 | 37.3 ms | 0.4 | 135 (5 × 27) |
| `Wish512` | 65536 B | 311.51 M | 4753.3 | 149 ms | 0.4 | 100 (5 × 20) |
| `Wish1024` | 32 B | 763.8 k | 23868.4 | 365 µs | 0.1 | 12785 (5 × 2557) |
| `Wish1024` | 128 B | 1.59 M | 12460.2 | 762 µs | 0.2 | 6360 (5 × 1272) |
| `Wish1024` | 512 B | 4.02 M | 7847.5 | 1.92 ms | 0.3 | 2545 (5 × 509) |
| `Wish1024` | 1024 B | 7.24 M | 7070.7 | 3.46 ms | 0.3 | 1415 (5 × 283) |
| `Wish1024` | 4096 B | 26.59 M | 6491.3 | 12.7 ms | 0.3 | 390 (5 × 78) |
| `Wish1024` | 8192 B | 52.47 M | 6404.7 | 25.1 ms | 0.3 | 200 (5 × 40) |
| `Wish1024` | 16384 B | 104.17 M | 6358.2 | 49.8 ms | 0.3 | 105 (5 × 21) |
| `Wish1024` | 65536 B | 414.04 M | 6317.8 | 198 ms | 0.3 | 100 (5 × 20) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `Wish512` | hash_32 | 14249 | 1684 KiB | 1768 KiB |
| `Wish512` | hash_128 | 14249 | 1660 KiB | 1780 KiB |
| `Wish512` | hash_512 | 14249 | 1692 KiB | 1756 KiB |
| `Wish512` | hash_1024 | 14249 | 1692 KiB | 1784 KiB |
| `Wish512` | hash_4096 | 14249 | 1676 KiB | 1784 KiB |
| `Wish512` | hash_8192 | 14249 | 1684 KiB | 1784 KiB |
| `Wish512` | hash_16384 | 14249 | 1684 KiB | 1788 KiB |
| `Wish512` | hash_65536 | 14249 | 1736 KiB | 1864 KiB |
| `Wish1024` | hash_32 | 14249 | 1668 KiB | 1732 KiB |
| `Wish1024` | hash_128 | 14249 | 1656 KiB | 1780 KiB |
| `Wish1024` | hash_512 | 14249 | 1692 KiB | 1760 KiB |
| `Wish1024` | hash_1024 | 14249 | 1672 KiB | 1740 KiB |
| `Wish1024` | hash_4096 | 14249 | 1684 KiB | 1788 KiB |
| `Wish1024` | hash_8192 | 14249 | 1696 KiB | 1772 KiB |
| `Wish1024` | hash_16384 | 14249 | 1668 KiB | 1808 KiB |
| `Wish1024` | hash_65536 | 14249 | 1736 KiB | 1864 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `Wish512` | KAT log (sha256 `7f476a6ec1b4f8a8…`) | `kat/hash-35/Wish512.log` |
| `Wish512` | timing hash_1024 | `records/hash-35/Wish512__hash_1024.json` |
| `Wish512` | timing hash_128 | `records/hash-35/Wish512__hash_128.json` |
| `Wish512` | timing hash_16384 | `records/hash-35/Wish512__hash_16384.json` |
| `Wish512` | timing hash_32 | `records/hash-35/Wish512__hash_32.json` |
| `Wish512` | timing hash_4096 | `records/hash-35/Wish512__hash_4096.json` |
| `Wish512` | timing hash_512 | `records/hash-35/Wish512__hash_512.json` |
| `Wish512` | timing hash_65536 | `records/hash-35/Wish512__hash_65536.json` |
| `Wish512` | timing hash_8192 | `records/hash-35/Wish512__hash_8192.json` |
| `Wish1024` | KAT log (sha256 `63ed769bd79a42ee…`) | `kat/hash-35/Wish1024.log` |
| `Wish1024` | timing hash_1024 | `records/hash-35/Wish1024__hash_1024.json` |
| `Wish1024` | timing hash_128 | `records/hash-35/Wish1024__hash_128.json` |
| `Wish1024` | timing hash_16384 | `records/hash-35/Wish1024__hash_16384.json` |
| `Wish1024` | timing hash_32 | `records/hash-35/Wish1024__hash_32.json` |
| `Wish1024` | timing hash_4096 | `records/hash-35/Wish1024__hash_4096.json` |
| `Wish1024` | timing hash_512 | `records/hash-35/Wish1024__hash_512.json` |
| `Wish1024` | timing hash_65536 | `records/hash-35/Wish1024__hash_65536.json` |
| `Wish1024` | timing hash_8192 | `records/hash-35/Wish1024__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

