<!-- synchronized report: hash-01/report.md -->
Candidate: AFS-TrEDM
Family: Symmetric (sponge hash)
Archive: [AFS-TrEDM.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/AFS-TrEDM.zip)

## hash-01-1: Partial-message bits control a machine branch

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Reference AFS-TrEDM-512/768/1024 on non-byte-aligned messages
Discovery: Trivial
Exploitation: Side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The final-bit framing loop passes each remaining message bit to `set_lane_bit_msb` (`afs_tredm.c:215`), which branches on that bit (`:99`). On x86-64, GCC `-O2` retains a `bt` followed by a conditional jump. Thus equal-length secret bitstrings can take different instruction paths. Byte-aligned inputs use a separate copy path; no timing extraction was demonstrated. See [constant_time.md](../constant-time/hash-01.md).

### Reproducing

Compile `afs_tredm.c` with `gcc -O2 -g -fPIC -c` and inspect `objdump -dSl` around `set_lane_bit_msb`; the message-bit path contains `bt`/`jae`.

