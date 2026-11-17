<!-- synchronized report: hash-16/report.md -->
Candidate: LLH
Family: Symmetric (bitsliced sponge with capacity feed-forward)
Archive: [LLH.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/LLH.zip) (SHA-256: `e79ca6ef17bcf0485ae2462cfe338e904f05551d7a8859271354d469072b3c2d`)

## hash-16-1: The hardware (RTL) implementation discards a short final block, giving immediate collisions in that implementation

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: The submitted Verilog hardware implementation only (Basic, HighPerformance and LowSize RTL), all four word sizes; the LLH algorithm, its specification and the reference and optimized C implementations are not affected
Discovery: Moderate
Exploitation: Immediate collisions in the hardware implementation between messages of equal length that agree on their full blocks; no search required; software digests are correct
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-17

This finding concerns the submitted hardware implementation, not the LLH algorithm: the specification and the C implementations handle these messages correctly. The RTL padder `msg_padder` receives the message as 128-bit bus words and shifts each word into a fixed slot of its buffer (`llh_padding.v:196,210`). A full block of r bits needs r/128 words, which fills the top r bits of the buffer. For the final partial block the padder accepts only as many words as the remaining L mod r bits need, and then keeps the top L mod r bits of the buffer (`:237-239`). Unless every word of the block was supplied, those bits are still zero, and the message bits sit lower in the buffer and are dropped. This does not depend on what the host sends, because the padder stops accepting words.

The affected lengths are those with 0 < L mod r ≤ r − 128: one half, three quarters, five sixths and seven eighths of all residues for the 256-, 512-, 768- and 1024-bit instances. In simulation of each of the three RTL variants at the 256-bit instance, the one-byte messages `00`, `5a` and `ff` all gave the digest `e7d61be6…f1a4`, which is the reference digest of `00`; the reference digest of `5a` is `fd6935ba…`. Any two messages of the same length that agree on their full blocks collide in the same way.

Two further defects appear in the same module. A 251-bit message gives a digest different from the reference, because the partial last byte is placed in the opposite bit order to the specification and the C code. An empty message never raises the completion signal. The permutation datapath itself matched the reference in all core-level cases, as did full blocks.

The host protocol was inferred from the RTL, since the test vectors and design document named in the package's `README.txt` are not in the archive. The reference and optimized C implementations compute these lengths correctly.

### Reproducing

```sh
sh hash-16/reproduce_asic_padder.sh
```

The witness simulates the three RTL variants with Icarus Verilog and compares them with the reference C build. It needs `iverilog` and `vvp`.
