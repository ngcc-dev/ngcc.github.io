<!-- synchronized from harness: hash-15/perf_x86_1.md -->
<p class="crumb"><a href="../index.md">Performance measurements</a> › <a href="index.md">x86_1</a> › <code>hash-15</code> · system: <strong>x86_1</strong> · <a href="../arm_1/hash-15.md">arm_1</a></p>

# hash-15 Litchi — performance on x86-64 (system x86_1)

Independent measurement following the structure of the NICCS x86 self-assessment guide, §3.5 (1)–(7). Not a submitter self-assessment.

## 1. Basic information

- Category: cryptographic hash algorithm; function: hash
- Algorithm: Litchi
- Implementation versions measured: reference
- Parameter sets: `litchi_512`, `litchi_768`, `litchi_1024`, `litchi_xof`
- Security evaluation: [hash-15 report](../../reports/hash-15.md)
- Measurement method: [x86_1 method](method.md)
- Submission: [NICCS page](https://www.niccs.org.cn/niccs/Round1Submissions4/pc/content/content_2101538083238924288.html)

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

Each library was checked against the submitted KAT vectors (SHA-256 manifest `hash-15/kat.sha256` in the harness) before timing.

| instance | build flags | KAT |
|---|---|---|
| `litchi_512` | guide | PASS |
| `litchi_768` | guide | PASS |
| `litchi_1024` | guide | PASS |
| `litchi_xof` | guide | PASS |

## 4. Performance

| instance | message | mean cycles | cycles/byte | mean time | MB/s | n |
|---|---|---|---|---|---|---|
| `litchi_512` | 32 B | 4129 | 129.0 | 1.97 µs | 16.2 | 100000 (5 × 20000) |
| `litchi_512` | 128 B | 8081 | 63.1 | 3.86 µs | 33.1 | 100000 (5 × 20000) |
| `litchi_512` | 512 B | 20.4 k | 39.8 | 9.73 µs | 52.6 | 100000 (5 × 20000) |
| `litchi_512` | 1024 B | 36.6 k | 35.8 | 17.5 µs | 58.5 | 100000 (5 × 20000) |
| `litchi_512` | 4096 B | 133.9 k | 32.7 | 64 µs | 64.0 | 73960 (5 × 14792) |
| `litchi_512` | 8192 B | 263.6 k | 32.2 | 126 µs | 65.1 | 40970 (5 × 8194) |
| `litchi_512` | 16384 B | 521.3 k | 31.8 | 250 µs | 65.4 | 19600 (5 × 3920) |
| `litchi_512` | 65536 B | 2.06 M | 31.5 | 986 µs | 66.4 | 5065 (5 × 1013) |
| `litchi_768` | 32 B | 4162 | 130.1 | 1.99 µs | 16.1 | 100000 (5 × 20000) |
| `litchi_768` | 128 B | 8374 | 65.4 | 4 µs | 32.0 | 100000 (5 × 20000) |
| `litchi_768` | 512 B | 24.1 k | 47.0 | 11.5 µs | 44.5 | 100000 (5 × 20000) |
| `litchi_768` | 1024 B | 44.4 k | 43.4 | 21.2 µs | 48.3 | 100000 (5 × 20000) |
| `litchi_768` | 4096 B | 174.2 k | 42.5 | 83.2 µs | 49.2 | 52910 (5 × 10582) |
| `litchi_768` | 8192 B | 346.3 k | 42.3 | 165 µs | 49.5 | 29860 (5 × 5972) |
| `litchi_768` | 16384 B | 687.0 k | 41.9 | 328 µs | 49.9 | 15550 (5 × 3110) |
| `litchi_768` | 65536 B | 2.74 M | 41.8 | 1.31 ms | 50.1 | 3695 (5 × 739) |
| `litchi_1024` | 32 B | 4111 | 128.5 | 1.97 µs | 16.3 | 100000 (5 × 20000) |
| `litchi_1024` | 128 B | 11.9 k | 92.7 | 5.67 µs | 22.6 | 100000 (5 × 20000) |
| `litchi_1024` | 512 B | 35.5 k | 69.3 | 16.9 µs | 30.2 | 100000 (5 × 20000) |
| `litchi_1024` | 1024 B | 66.7 k | 65.2 | 31.9 µs | 32.1 | 100000 (5 × 20000) |
| `litchi_1024` | 4096 B | 256.1 k | 62.5 | 122 µs | 33.5 | 37165 (5 × 7433) |
| `litchi_1024` | 8192 B | 502.0 k | 61.3 | 240 µs | 34.2 | 19695 (5 × 3939) |
| `litchi_1024` | 16384 B | 1.01 M | 61.6 | 482 µs | 34.0 | 9835 (5 × 1967) |
| `litchi_1024` | 65536 B | 4.01 M | 61.2 | 1.92 ms | 34.2 | 2565 (5 × 513) |
| `litchi_xof` | 32 B | 4291 | 134.1 | 2.05 µs | 15.6 | 100000 (5 × 20000) |
| `litchi_xof` | 128 B | 8317 | 65.0 | 3.98 µs | 32.2 | 100000 (5 × 20000) |
| `litchi_xof` | 512 B | 31.2 k | 61.0 | 14.9 µs | 34.3 | 100000 (5 × 20000) |
| `litchi_xof` | 1024 B | 58.0 k | 56.6 | 27.7 µs | 37.0 | 100000 (5 × 20000) |
| `litchi_xof` | 4096 B | 217.8 k | 53.2 | 104 µs | 39.4 | 46455 (5 × 9291) |
| `litchi_xof` | 8192 B | 438.5 k | 53.5 | 209 µs | 39.1 | 23230 (5 × 4646) |
| `litchi_xof` | 16384 B | 872.2 k | 53.2 | 417 µs | 39.3 | 12235 (5 × 2447) |
| `litchi_xof` | 65536 B | 3.53 M | 53.8 | 1.68 ms | 38.9 | 3030 (5 × 606) |

## 5. Resource consumption

Static memory is approximated by the library's loadable ELF segments; peak memory is the process high-water mark (VmHWM) including the benchmark driver and libc, so both are upper-bound proxies rather than isolated algorithm memory.

| instance | operation | static: ELF image (bytes) | baseline RSS | peak RSS |
|---|---|---|---|---|
| `litchi_512` | hash_32 | 14981 | 1672 KiB | 1760 KiB |
| `litchi_512` | hash_128 | 14981 | 1696 KiB | 1760 KiB |
| `litchi_512` | hash_512 | 14981 | 1680 KiB | 1744 KiB |
| `litchi_512` | hash_1024 | 14981 | 1676 KiB | 1740 KiB |
| `litchi_512` | hash_4096 | 14981 | 1688 KiB | 1776 KiB |
| `litchi_512` | hash_8192 | 14981 | 1692 KiB | 1756 KiB |
| `litchi_512` | hash_16384 | 14981 | 1700 KiB | 1776 KiB |
| `litchi_512` | hash_65536 | 14981 | 1728 KiB | 1796 KiB |
| `litchi_768` | hash_32 | 12725 | 1672 KiB | 1776 KiB |
| `litchi_768` | hash_128 | 12725 | 1656 KiB | 1780 KiB |
| `litchi_768` | hash_512 | 12725 | 1664 KiB | 1776 KiB |
| `litchi_768` | hash_1024 | 12725 | 1668 KiB | 1732 KiB |
| `litchi_768` | hash_4096 | 12725 | 1684 KiB | 1772 KiB |
| `litchi_768` | hash_8192 | 12725 | 1684 KiB | 1780 KiB |
| `litchi_768` | hash_16384 | 12725 | 1696 KiB | 1760 KiB |
| `litchi_768` | hash_65536 | 12725 | 1744 KiB | 1844 KiB |
| `litchi_1024` | hash_32 | 12661 | 1684 KiB | 1776 KiB |
| `litchi_1024` | hash_128 | 12661 | 1680 KiB | 1776 KiB |
| `litchi_1024` | hash_512 | 12661 | 1692 KiB | 1756 KiB |
| `litchi_1024` | hash_1024 | 12661 | 1628 KiB | 1756 KiB |
| `litchi_1024` | hash_4096 | 12661 | 1656 KiB | 1780 KiB |
| `litchi_1024` | hash_8192 | 12661 | 1672 KiB | 1736 KiB |
| `litchi_1024` | hash_16384 | 12661 | 1684 KiB | 1772 KiB |
| `litchi_1024` | hash_65536 | 12661 | 1752 KiB | 1816 KiB |
| `litchi_xof` | hash_32 | 13253 | 1648 KiB | 1772 KiB |
| `litchi_xof` | hash_128 | 13253 | 1688 KiB | 1772 KiB |
| `litchi_xof` | hash_512 | 13253 | 1684 KiB | 1756 KiB |
| `litchi_xof` | hash_1024 | 13253 | 1668 KiB | 1776 KiB |
| `litchi_xof` | hash_4096 | 13253 | 1696 KiB | 1760 KiB |
| `litchi_xof` | hash_8192 | 13253 | 1676 KiB | 1780 KiB |
| `litchi_xof` | hash_16384 | 13253 | 1708 KiB | 1784 KiB |
| `litchi_xof` | hash_65536 | 13253 | 1732 KiB | 1824 KiB |

## 7. Raw evidence index

Paths are relative to `performance/data/x86_1/` in the [harness](https://github.com/ngcc-dev/ngcc-harness); each JSON file records its commands, environment and trials.

| instance | item | file |
|---|---|---|
| `litchi_512` | KAT log (sha256 `4cee4d72f05f9c85…`) | `kat/hash-15/litchi_512.log` |
| `litchi_512` | timing hash_1024 | `records/hash-15/litchi_512__hash_1024.json` |
| `litchi_512` | timing hash_128 | `records/hash-15/litchi_512__hash_128.json` |
| `litchi_512` | timing hash_16384 | `records/hash-15/litchi_512__hash_16384.json` |
| `litchi_512` | timing hash_32 | `records/hash-15/litchi_512__hash_32.json` |
| `litchi_512` | timing hash_4096 | `records/hash-15/litchi_512__hash_4096.json` |
| `litchi_512` | timing hash_512 | `records/hash-15/litchi_512__hash_512.json` |
| `litchi_512` | timing hash_65536 | `records/hash-15/litchi_512__hash_65536.json` |
| `litchi_512` | timing hash_8192 | `records/hash-15/litchi_512__hash_8192.json` |
| `litchi_768` | KAT log (sha256 `bfc1e3922bf23b1e…`) | `kat/hash-15/litchi_768.log` |
| `litchi_768` | timing hash_1024 | `records/hash-15/litchi_768__hash_1024.json` |
| `litchi_768` | timing hash_128 | `records/hash-15/litchi_768__hash_128.json` |
| `litchi_768` | timing hash_16384 | `records/hash-15/litchi_768__hash_16384.json` |
| `litchi_768` | timing hash_32 | `records/hash-15/litchi_768__hash_32.json` |
| `litchi_768` | timing hash_4096 | `records/hash-15/litchi_768__hash_4096.json` |
| `litchi_768` | timing hash_512 | `records/hash-15/litchi_768__hash_512.json` |
| `litchi_768` | timing hash_65536 | `records/hash-15/litchi_768__hash_65536.json` |
| `litchi_768` | timing hash_8192 | `records/hash-15/litchi_768__hash_8192.json` |
| `litchi_1024` | KAT log (sha256 `7318526a5770f9b9…`) | `kat/hash-15/litchi_1024.log` |
| `litchi_1024` | timing hash_1024 | `records/hash-15/litchi_1024__hash_1024.json` |
| `litchi_1024` | timing hash_128 | `records/hash-15/litchi_1024__hash_128.json` |
| `litchi_1024` | timing hash_16384 | `records/hash-15/litchi_1024__hash_16384.json` |
| `litchi_1024` | timing hash_32 | `records/hash-15/litchi_1024__hash_32.json` |
| `litchi_1024` | timing hash_4096 | `records/hash-15/litchi_1024__hash_4096.json` |
| `litchi_1024` | timing hash_512 | `records/hash-15/litchi_1024__hash_512.json` |
| `litchi_1024` | timing hash_65536 | `records/hash-15/litchi_1024__hash_65536.json` |
| `litchi_1024` | timing hash_8192 | `records/hash-15/litchi_1024__hash_8192.json` |
| `litchi_xof` | KAT log (sha256 `7e223b5a5121b980…`) | `kat/hash-15/litchi_xof.log` |
| `litchi_xof` | timing hash_1024 | `records/hash-15/litchi_xof__hash_1024.json` |
| `litchi_xof` | timing hash_128 | `records/hash-15/litchi_xof__hash_128.json` |
| `litchi_xof` | timing hash_16384 | `records/hash-15/litchi_xof__hash_16384.json` |
| `litchi_xof` | timing hash_32 | `records/hash-15/litchi_xof__hash_32.json` |
| `litchi_xof` | timing hash_4096 | `records/hash-15/litchi_xof__hash_4096.json` |
| `litchi_xof` | timing hash_512 | `records/hash-15/litchi_xof__hash_512.json` |
| `litchi_xof` | timing hash_65536 | `records/hash-15/litchi_xof__hash_65536.json` |
| `litchi_xof` | timing hash_8192 | `records/hash-15/litchi_xof__hash_8192.json` |

Scripts: `performance/campaign.py`, `performance/ngcc_perf.c`, `performance/hashprof/` in the [harness](https://github.com/ngcc-dev/ngcc-harness).

