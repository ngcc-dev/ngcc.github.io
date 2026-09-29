# Performance

Independent cycle-count measurements of the NGCC Round 1 candidates. Each system summary reports ICCS-facing parameter sets, primitive operations, and the public-key schemes' share spent in ICCS placeholder hash functions, and hash timings relative to the ICCS placeholder `pseudoXOF` with the same message length and output width, itself timed alongside the ICCS helpers. Per-candidate pages retain every measured implementation, including non-ICCS variants omitted from the aggregate table.

| system | architecture | machine |
|---|---|---|
| [x86_1](x86_1/index.md) | x86_64 | Intel Core i7-12700 (Alder Lake), one performance core, turbo off, fixed 2.1 GHz, SMT off |
| [arm_1](arm_1/index.md) | aarch64 | Qualcomm Snapdragon X Elite X1E-78-100 (Oryon), one core, clock pinned at 2.71 GHz (cpufreq performance, min = max), no SMT |

The [symmetric cryptography survey](symmetric-survey.md) records how each public-key submission implements hashing and randomness. Per-candidate pages include the measurement method, KAT status, sizes, memory proxies and raw-evidence index.
