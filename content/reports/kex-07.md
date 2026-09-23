<!-- synchronized report: kex-07/report.md -->
Candidate: NEV-AKE
Family: Lattice (NTRU/Ring-LWE AKE)
Archive: [NEV-AKE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NEV-AKE.zip) (SHA-256: `da75005b4060167f25125cbd1a769ed872c8b6fcb770fe0827a599e44536e8e6`)

## kex-07-1: Both party identities are hard-wired to zero

Severity: Medium
Status: Confirmed
Layer: Implementation
Affected: Uniform-API reference wrappers, all nine parameter sets
Discovery: Trivial
Exploitation: Integration-dependent; no complete UKS attack demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

Every submitted `kat_test/KEX_AlgorithmInstance.c` allocates the initiator and responder identities as all-zero `SEED_BYTES` arrays. The wrappers pass those constants into responder processing and initiator key derivation for all nine profiles.

The official `KEX_AlgorithmInstance.h` API exposes no identity argument, so the wrapper had no channel through which an application could supply the modeled identities. A sound integration could instead derive stable identities from the parties' public keys; hard-wiring both to zero removes the binding entirely.

The core `ake.c` code hashes both identities into the session-key computations, and the specification's CK+ model distinguishes the session holder and peer identities `i` and `j`. The wrapper therefore collapses every deployment and every pair of parties onto one fixed identity pair instead of instantiating the protocol's modeled identity binding.

This is a confirmed integration security defect. The transcript still contains cryptographic public keys, and no complete unknown-key-share or impersonation attack was demonstrated through the fixed API, so this report does not claim a proved AKE break beyond the missing identity binding.

### Reproducing

Fetch the official archive and inspect the zero-initialized `idi` and `idj`
arrays at lines 105–106 and 165–166 of
`NEV-AKE-C1/kat_test/KEX_AlgorithmInstance.c`; the other eight reference
wrappers have the same assignments. Compare the wrapper API header, which has
no caller-supplied identity parameter, with the identity inputs to `ake.c`.

```sh
IDS=kex-07 ./download.sh
./extract.sh kex-07
rg -n 'unsigned char id[ij]\[SEED_BYTES\] = \{0\}' 'kex-07/Implementations and Test_Vectors/Implementations/Reference_Implementation' --glob KEX_AlgorithmInstance.c
```
