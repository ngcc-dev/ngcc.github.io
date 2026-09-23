<!-- synchronized report: kem-32/report.md -->
Candidate: QCTM
Family: Code-based (quasi-cyclic twisted McEliece)
Archive: [QCTM.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QCTM.zip) (SHA-256: `24a3986a4fbb852a677267a6443756328eae3642af770e767fe38f8291f294db`)

## kem-32-1: Debug path retains the secret error vector

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all three parameter sets when tracing is enabled
Discovery: Trivial
Exploitation: Requires stderr visibility or local/in-process memory access
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

When the `LOCALLY_QUASI_CYCLIC_TWISTED_MCELIECE_TRACE_DEC` environment variable is present, encapsulation copies the fixed-weight secret error positions into file-static process-global storage. The same opt-in trace path prints decoder stages, syndrome-difference counts, decoded weight, and failure-location diagnostics to standard error.

The logic is present in the compiled QCTM128, QCTM256, and QCTM512 reference sources. The retained error positions are secret per-encapsulation material and should be erased after ciphertext construction, not persisted for a later decoder trace.

The static buffer has no exported accessor, so merely setting the environment variable does not reveal its contents to a remote KEM caller. Exploitation additionally requires stderr visibility, local/in-process memory access, or another disclosure primitive. This is a confirmed implementation-security and secret-lifetime defect, not a demonstrated remote key-recovery attack.

### Reproducing

This is a source-level secret-lifetime check, not a remote exploit. Fetch the
official archive, then inspect the QCTM128 reference `kem.c` at lines 15–20
(file-static buffer), 523–531 (trace use), and 641–645 (copy from the fresh
encapsulation error). The QCTM256 and QCTM512 reference files have the same
pattern.

```sh
IDS=kem-32 ./download.sh
./extract.sh kem-32
rg -n 'debug_last_error|TRACE_DEC' kem-32/Implementations/Reference_Implementation/QCTM*/kem.c
```
