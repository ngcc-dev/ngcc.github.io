<!-- synchronized report: hash-01/report.md -->
Candidate: AFS-TrEDM
Family: Symmetric (sponge hash)
Archive: [AFS-TrEDM.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/AFS-TrEDM.zip) (SHA-256: `6a4b3d3ca5c225ad7d8714878e12f10cbf92aa6e081a8b85f504b6eeb2f4188b`)

## hash-01-1: Partial-message bits control a machine branch

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: Reference AFS-TrEDM-512/768/1024 on non-byte-aligned messages
Discovery: Trivial
Exploitation: Side-channel dependent
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The final-bit framing loop passes each remaining message bit to `set_lane_bit_msb` (`afs_tredm.c:215`), which branches on that bit (`:99`). On x86-64, GCC `-O2` retains a `bt` followed by a conditional jump. Thus equal-length secret bitstrings can take different instruction paths. Byte-aligned inputs use a separate copy path; no timing extraction was demonstrated. See [constant_time.md](../constant-time/hash-01.md).

Constant-time fix (easy, hence Low): set each bit arithmetically, e.g. `lane ^= (uint64_t)bit << pos`, instead of branching on it.

### Reproducing

Compile `afs_tredm.c` with `gcc -O2 -g -fPIC -c` and inspect `objdump -dSl` around `set_lane_bit_msb`; the message-bit path contains `bt`/`jae`.

## hash-01-2: Missing final-block separation gives a 2^64-query distinguisher

Severity: High
Status: Confirmed
Layer: Design
Affected: Specified AFS-TrEDM-512, -768, and -1024 constructions and reference implementations
Discovery: Moderate
Exploitation: Approximately 2^64 permutation evaluations; this is an indifferentiability distinguisher, not a collision or preimage
Credit: Qinghe Crypto Group
Date: 2026-09-29
Original source: [CryptHash Forum post](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/IBTHTO24MZQCJUE4GCUI3HJKPA2B4Q6E/)

AFS-TrEDM applies the same absorbing core to ordinary and final framed blocks. Write the state after hashing `M` as `R || z || u`, where `R` is the rate, `z` is the published digest, and `u` is the only unrevealed 64-bit capacity suffix. Hash the distinct extended message `M' = P(M) || R`, where `P(M)` is the complete rate-aligned framing of `M`. Processing its `P(M)` prefix recreates the original final state; absorbing `R` then cancels the rate before `g`, leaving `0^r || z || u`. The following core output and the fixed fresh framing block for `M'` therefore depend only on public `z` and guessed `u`.

A distinguisher enumerates the `2^64` possible values of `u`, fixes the resulting candidate-digest set, obtains `R` through later permutation queries, and tests whether `H(P(M) || R)` belongs to that set. The real construction always matches, whereas an ideal `d`-bit oracle matches a fixed set of at most `2^64` values with probability at most `2^(64-d)`. This contradicts the specification's ideal-permutation indifferentiability and length-extension discussion. It does not establish a collision, preimage, or second preimage, so the violation of this additional claimed property is High rather than Critical under the classification policy. Capacity-domain separation for the actual final block would prevent the replay.

### Reproducing

```sh
python3 hash-01/reproduce_final_block_replay.py
```

The witness compiles the archived permutation at all three parameter sets. It checks the candidate's framing against `CryptHash`, confirms that absorbing the exposed rate produces exactly the same complete state as starting that call from `0^r || z || u`, processes the fresh extended-message padding, and matches the resulting candidate to the full submitted hash. Flipping one bit of the appended rate is a nonmatching control. The script certifies the construction underlying the `2^64` enumeration; it does not execute that enumeration.
