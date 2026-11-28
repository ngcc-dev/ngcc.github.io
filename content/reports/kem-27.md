<!-- synchronized report: kem-27/report.md -->
Candidate: NTRE
Family: Lattice-based (NTRU) KEM
Archive: [NTRE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/NTRE.zip) (SHA-256: `9c0bad4c4846998df1214ba562e1c3b8aece6b69f08234a9bb0d89e3a5a4ea9a`)

## kem-27-1: NTRE-512's 256-bit secret seed caps offline key-recovery work

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: NTRE-512 reference and optimized implementations
Discovery: Moderate
Exploitation: At most 2^256 seed trials against a public key, versus the 512-bit target
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23
Follow-up source: [NTRE team's confirmation and correction plan](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/OAGYDCAYEJTJ6WE5PHBNNCTAGDZ57LXD/)

NTRE-512's reference key generator samples the private NTRU polynomial `f = 2f' + 1` from a single 32-byte seed through `sample_psi1`. This restricts its nominally 512-bit secret-key space to at most 2^256 possibilities. The public key permits an efficient offline test of each guess: compute `g = h·f` and check whether its coefficients have the required small distribution (`g = 2g'`). A surviving `f` is sufficient to reconstruct the decapsulation key (`f`, the public key, and its public hash). Thus exhaustive seed search recovers a working key in at most 2^256 trials, independent of the claimed hardness of the full-distribution NTRU problem.

This is an implementation-instantiation weakness, not a claim that the specification's ideal `Sample(n)` has only 256 bits of entropy. The full 2^256 search is far beyond available resources. A scaled public-key attack enumerates 2^12 planted seed candidates, finds the unique matching `f`, reconstructs the official secret-key layout and correctly decapsulates ten fresh ciphertexts; ten deliberately wrong-key controls fail.

The NTRE team confirms that `NTRE_SYMBYTES` is 32 in every reference and
optimized parameter-set copy, while Algorithm 5 requires 64 bytes. The 256-bit
root does not miss the lower sets' classical targets; this report remains
scoped to NTRE-512.

### Proposed fixes

The [NTRE team's response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/OAGYDCAYEJTJ6WE5PHBNNCTAGDZ57LXD/) proposes correcting `NTRE_SYMBYTES` and regenerating the KATs. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kem-27 exploit
```

The script builds the submitted NTRE-512 sources in a temporary directory and prints `CONFIRMED kem-27-1`. It explicitly labels the scaled seed subspace and does not present this as a full-size key recovery.

## kem-27-2: The message-dependent error sampler branches on every message bit

Severity: Low
Status: Confirmed
Layer: Side-channel
Affected: NTRE-128, -256 and -512; reference and optimized implementations
Discovery: Trivial
Exploitation: Local branch trace of the encapsulated message, and of the decrypted message during re-encryption; no extraction demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-11-15

Encryption derives its error polynomial from the message: `poly_cbd1_prime` sets each coefficient to `beta0 ? (1 - 2*beta1) : 0`, where `beta0` is a message bit (`src/poly.c:60–76` in the reference; an unrolled form of the same expression in the optimized tree). `kem_enc` calls it on the fresh message, which determines the shared secret, and `kem_dec` calls it on the decrypted message when it re-encrypts, before the validity decision takes effect (`KEM_AlgorithmInstance.c:69,151,203`).

At the Makefile's `-O2`, GCC 15.2 compiles the select to a test of the message bit and a conditional jump. A branch-trace observer therefore reads the message bit by bit, and the amount of work follows its Hamming weight. No timing oracle or extraction was built.

Constant-time fix (easy, hence Low): multiply by the bit or apply it as a mask.

### Reproducing

```sh
d=kem-27/Implementations/Reference_Implementation/NTRE-256
gcc -O2 -std=c99 -g -w -I"$d" -I"$d/src" -c "$d/src/poly.c" -o /tmp/ntre_poly.o
objdump -dl --no-show-raw-insn /tmp/ntre_poly.o |
  awk '/^\/.*:[0-9]+/{loc=$1} /\tj[a-z]+ /{if ($2!="jmp") print loc, $2}' | grep 'poly.c:72 '
```

The listing shows a conditional jump attributed to the select at `poly.c:72`. No timing was measured by this witness.

## kem-27-3: The specified component-wise NTT does not exist for any NTRE parameter set

Severity: Low
Status: Confirmed
Layer: Design
Affected: The written specification (§1.1, Algorithms 8–10, §2.2), all three parameter sets; the submitted implementations use a different transform and are self-consistent
Discovery: Moderate
Exploitation: Keys and ciphertexts are encodings of a transform that the specification does not define and that cannot exist as described; an implementation written from it cannot interoperate with the submitted code; no security consequence
Credit: Zhengyang Wang, Yichuan Cao, Kunyu Wu, Hongbo Li and Xiao-Shan Gao, with MechCrypto assistance
Date: 2026-11-28
Reference: [Wang, Cao, Wu, Li and Gao, *MechCrypto: Agent-Assisted Cryptanalysis of the First-Round NGCC Candidates*, ePrint 2026/3050](https://eprint.iacr.org/2026/3050); [result for this candidate](https://github.com/MechMath/NGCC-results/tree/main/key-encapsulation/kem-27_NTRE)

Section 1.1 (physical p. 4) introduces an NTT that maps a polynomial of `R_q = Z_q[X]/(X^n − X^(n/2) + 1)` to a vector of `n` elements of `Z_q`, and states that multiplication in `R_q` becomes component-wise multiplication of these vectors. Algorithms 8–10 (physical p. 7) compute `ĥ = ĝ ∘ f̂^-1` and `ĉ = ĥ ∘ r̂ + ê` in that domain, and the public key, secret key and ciphertext are the byte encodings of `ĥ`, `f̂` and `ĉ`. The specification gives no roots of unity, ordering or layer structure.

Such a transform does not exist for the three parameter sets. `X^n − X^(n/2) + 1` is the cyclotomic polynomial of index `3n`, which splits into linear factors modulo a prime `q` only if `3n` divides `q − 1`. For `(n, q) = (648, 2593)`, `(1296, 2917)` and `(2304, 3457)` the remainders of `q − 1` modulo `3n` are 648, 2916 and 3456, and the order of `q` modulo `3n` is 3, 4 and 2, so the irreducible factors have those degrees. Section 2.2 (physical p. 12) also requires `q ≡ 1 (mod n)`, which fails for the second and third sets.

The submitted code stops its transform at blocks of 3 coefficients for NTRE-128 and of 4 for NTRE-256 and NTRE-512 (`NTRE_D`, `src/params.h:8`), and multiplies and inverts block by block (`src/poly.c:92–146`). The serialised keys and ciphertexts hold these blocks (`KEM_AlgorithmInstance.c:72,108–109`). The block size, the constants and their order appear only in the code, and NTRE-512 uses blocks of four although quadratic factors exist. The byte formats therefore cannot be derived from the specification. The ring and the scheme are unaffected.

### Reproducing

```sh
python3 -c "print([((q-1)%(3*n), (q-1)%n) for n,q in ((648,2593),(1296,2917),(2304,3457))])"
grep -n 'define NTRE_[NQD] ' kem-27/Implementations/Reference_Implementation/NTRE-*/src/params.h
```

This is a source witness. The first command prints the remainders `(648, 0)`, `(2916, 324)` and `(3456, 1152)`.
