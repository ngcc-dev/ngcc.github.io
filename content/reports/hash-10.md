<!-- synchronized report: hash-10/report.md -->
Candidate: FEILIAN
Family: Symmetric (matrix-based hash)
Archive: [FEILIAN.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/FEILIAN.zip) (SHA-256: `876082a40ecf3b25d8b19478cbfeab4bd5f96ff7a293aacc5b57a9f73c2ff26c`)

## hash-10-1: Padding-allocation failure returns a successful all-zero digest

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized FEILIAN512/768/1024 C implementations
Discovery: Moderate
Exploitation: Resource-contingent false-success digest; not a normal-operation cryptanalytic collision
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance; optimized scope verified by Mounir Idrassi <mounir@amcrypto.jp>
Date: 2026-09-23
Follow-up source: [Mounir Idrassi's GitHub issue #21, 2026-09-26](https://github.com/ngcc-dev/ngcc-harness/issues/21)

FEILIAN's `pad_message` returns zero when its padded-message allocation fails. The hash core then zeroes the requested digest, while the public `CryptHash` API returns success. Under a bounded address space, two distinct 16-MiB byte-aligned messages both returned `0` and the same all-zero 512-bit digest. A changed-message control yields distinct digests with available memory, and the ordinary FEILIAN512 KAT passes.

This is a resource-contingent implementation failure, not a collision in the successfully executed FEILIAN construction. It is relevant when a caller accepts a digest after the library silently fails; allocation failure should be returned as an error.

Mounir Idrassi's follow-up source review confirms the identical failure path in `FEILIAN_SIMD512`, `FEILIAN_SIMD768` and `FEILIAN_SIMD1024`: `pad_message` returns zero, the internal routine clears the digest, and the public wrapper still returns success. This extends the affected scope but is not a separate vulnerability.

### Reproducing

```sh
make -C hash-10 exploit
```

The Linux witness preallocates the input, caps process virtual memory at its current use plus 4 MiB, and verifies both successful zero-digest responses.

## hash-10-2: Three FEILIAN RTL cores have trivial zero-extension collisions

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Submitted FEILIAN_1SC, FEILIAN_4SC and FEILIAN_8SC RTL implementations
Discovery: Trivial
Exploitation: Immediate full-round collision; no search required
Credit: Mounir Idrassi <mounir@amcrypto.jp>
Date: 2026-09-26
Original source: [GitHub issue #18](https://github.com/ngcc-dev/ngcc-harness/issues/18)

RTL here means the submitted synthesizable SystemVerilog in the optional `FEILIAN/Implementations/Additional_Implementation` tree. The 1SC, 2SC, 4SC and 8SC names denote hardware architectures with different SubColumn parallelism.

The specification increments the cumulative bit count to include the current block before compression (§2.3). These three wrappers instead form `cf_domain` from `hashed_bits_reg`, which counts only completed blocks, and add the current block after compression finishes (`core.sv:135,157` in 1SC/4SC; `:137,160` in 8SC). Their zero-only padding and final flag therefore do not distinguish final blocks that differ only by trailing zero bytes.

Further extension to Mounir Idrassi's analysis: the canonical byte messages `0x61` and `0x6100` are both presented to the sole (first-and-final) compression call as the same zero-padded 1024-bit block, the same final flag and counter zero. Full RTL simulation confirms identical 1024-bit digests in 1SC, 4SC and 8SC. The 2SC wrapper computes `hashed_bits_updated` before compression (`core.sv:120-141`) and produces different digests for the pair, providing a clean control. This is a break of the submitted hardware hashes, not of the correctly counted C implementations.

### Reproducing

With Verilator installed:

```sh
make -C hash-10 rtl-exploit
```

The witness compiles all four submitted cores, prints three `ATTACK hash-10-2 ... CONFIRMED` lines, and shows the 2SC control as `NOT-CONFIRMED`.

## hash-10-3: The specification, examples and RTL define incompatible FEILIAN variants

Severity: Low
Status: Confirmed
Layer: Design
Affected: Submitted FEILIAN specification, Appendix B examples and RTL packages
Discovery: Moderate
Exploitation: Interoperability and analysis-target failure; no collision in the C implementations demonstrated
Credit: Mounir Idrassi <mounir@amcrypto.jp>
Date: 2026-09-26
Original source: [GitHub issue #19](https://github.com/ngcc-dev/ngcc-harness/issues/19)

Several definitions conflict. Chapter 2 prints IV word 7 as `3D84...` (line 101), while its stated pi derivation, C and RTL give `3F84...`. The AddConstant diagram places the tweak in row 1 and constants in row 3, while Appendix A, C and RTL reverse them. C and 2SC encode the 128-bit counter high word first, while 1SC/4SC/8SC encode it low word first. All four RTL packages hard-code version `0x400` and a 1024-bit digest even though the submitted `FEILIAN/Implementations/README.txt:21,23` labels 1SC and 4SC as 512-bit designs.

Appendix B is internally mixed as well. Independent evaluation of all six examples shows that the 1024-bit examples use the true cumulative message lengths, while the 512- and 768-bit examples use cumulative padded-block lengths. The latter convention loses the logical-length binding on which zero padding relies. The ordinary C implementations and their KATs use true lengths, so this is an ambiguity and conformance defect rather than a full-round attack on those implementations.

### Reproducing

The review package at tag `v1.0.1`, commit `16567114688adf5cae44d65f45d88ed308d0f893`, provides the numerical checker. Its quick mode reports six digests, nine initial states, 45 round snapshots and nine domains verified, and identifies the true-count versus padded-count split. Verify the exact commit before running it:

```sh
git clone --depth 1 --branch v1.0.1 https://github.com/amcrypto-jp/feilian-cryptanalysis.git /tmp/feilian-review &&
  test "$(git -C /tmp/feilian-review rev-parse HEAD)" = 16567114688adf5cae44d65f45d88ed308d0f893 &&
  python3 /tmp/feilian-review/run.py --mode quick --output-dir /tmp/feilian-quick
```

## hash-10-4: C implementations hash storage bits outside partial-byte messages

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized FEILIAN512/768/1024 C implementations
Discovery: Trivial
Exploitation: Noncanonical encodings of one bitstring produce different digests; no collision demonstrated
Credit: Mounir Idrassi <mounir@amcrypto.jp>
Date: 2026-09-26
Original source: [GitHub issue #20](https://github.com/ngcc-dev/ngcc-harness/issues/20)

For a non-byte-aligned input, `pad_message` copies `(msg_bits + 7) / 8` complete bytes without masking the unused low bits (`CryptHash_AlgorithmInstance.c:84-90`; SIMD source `:192-198`). The API length declares those bits outside the message, and §2.3 specifies zero padding. Consequently byte buffers `80` and `81`, each declared to contain the same one-bit message `1`, produce different digests in every C instance. Passing KATs do not cover this condition because their generator clears unused bits.

This is a bitstring-API correctness failure, but unlike `hash-05-3` no collision between distinct declared bitstrings has been demonstrated. Masking the unused low bits before compression repairs the defect.

### Reproducing

```sh
make -C hash-10 unused-bits
```

The runtime witness exercises the three reference libraries; source inspection confirms the identical unmasked-copy path in the three optimized implementations.

## hash-10-5: C input-length conversion and padding arithmetic are unchecked

Severity: Info
Status: Confirmed
Layer: Implementation
Affected: Reference and optimized FEILIAN512/768/1024 C implementations, especially platforms where size_t is narrower than unsigned long long
Discovery: Trivial
Exploitation: Extreme-length contract failure; no memory-safety exploit demonstrated
Credit: Mounir Idrassi <mounir@amcrypto.jp>
Date: 2026-09-26
Original source: [GitHub issue #20](https://github.com/ngcc-dev/ngcc-harness/issues/20)

The public API accepts an `unsigned long long` bit length and casts it to `size_t` without checking representability (`CryptHash_AlgorithmInstance.c:345-356`; SIMD source `:405-416`). `pad_message` then rounds with `msg_bits + 7` and adds the padding length without overflow checks. A narrower `size_t` truncates valid API values; even at equal width, values near `SIZE_MAX` wrap during rounding. The internal two-word counter therefore does not make the one-shot implementation support its written length domain.

This is a platform- and extreme-input contract defect, not a demonstrated ordinary-input collision or out-of-bounds access. On a 64-bit platform, the wrap requires a declared input near 2^64 bits, which cannot be held in memory; narrower `size_t` platforms can reach the conversion limit earlier. That limited practical impact warrants Info. The implementation should reject unrepresentable lengths and check every rounding and allocation calculation before reading the message.

### Reproducing

Inspect the conversions and arithmetic at the cited reference and SIMD source lines. The issue's source manifest confirms the same pattern in all six C instances.
