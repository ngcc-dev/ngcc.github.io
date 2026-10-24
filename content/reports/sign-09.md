<!-- synchronized report: sign-09/report.md -->
Candidate: DOVE
Family: Multivariate (Double Oil-and-Vinegar)
Archive: [DOVE.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DOVE.zip) (SHA-256: `19169e545f6a6fd90b844b0deb72db81b5eb73c136873d1dae113c2c39d1c6e0`)

## sign-09-1: The unauthenticated signature salt invalidates the salted-target analysis

Severity: Medium
Status: Confirmed
Layer: Design
Affected: DOVE-128, -256 and -512, both classic and pkc_skc variants
Discovery: Trivial
Exploitation: Trivial signature malleability; no hash-independent EUF-CMA forgery demonstrated
Credit: Dariia Porechna ([dariolina](https://github.com/dariolina))
Date: 2026-09-22
Original source: [GitHub issue #9](https://github.com/ngcc-dev/ngcc-harness/issues/9)

DOVE's specified Sign and Verify algorithms compute the target from `message || seed_pk`; Verify never reads the salt included in the signature. The submitted implementations follow this construction. Flipping any salt bit therefore gives a distinct accepted signature on the same message, and the specification's §6.1.1.1 analysis of a target `Hash(µ || salt)` does not apply to the submitted algorithm. This is a design-level transcript/proof mismatch independent of the hash selected.

The original issue also analyzes the concrete SM3 `pseudoXOF`, but attacks relying on that correctness-only placeholder are outside this report. Only EUF-CMA is claimed in the specification; salt malleability alone does not violate that claim, and no hash-independent new-message forgery is demonstrated.

### Reproducing

```sh
make -C sign-09 exploit
```

The static validator checks all four submitted classic/pkc_skc source copies for the absent salt binding. The runtime witness flips a salt bit in a genuine DOVE-128 signature: verification still accepts it, while a changed-message control rejects. No full-size collision search was attempted.

## sign-09-2: The EUF-CMA reduction treats trapdoor recovery as public-key indistinguishability

Severity: Medium
Status: Proof gap
Layer: Design
Affected: DOVE-128, -256 and -512 security proof
Discovery: Moderate
Exploitation: The stated assumption does not justify the Game 0-to-1 transition; no forgery or key recovery is demonstrated
Credit: 潇湘 (lxx, NGCC PKC Forum sender)
Date: 2026-10-15
Original source: [DOVE assessment attached to the PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PLF54PXYLAT2LQFQLJWN5LMKWSWWSM7O/attachment/7/DOVE_security_assessment.md)

Definition 2 (§4.3.2, physical p. 14) defines DOVE-UOV as finding a trapdoor or equivalent oil subspace from a real public key. Theorem 1's Game 1 (§4.4, physical pp. 14–15) instead replaces the trapdoor-derived public blocks with random symmetric matrices. It bounds the resulting change in the forger's success probability by the ability to *distinguish* those two public-key distributions, calling that “precisely the definition” of DOVE-UOV.

Trapdoor recovery is a search problem; public-key indistinguishability is a decision problem. Hardness of the former does not, by itself, bound the latter, so the stated DOVE-UOV assumption does not justify this game hop. A separate decisional assumption or a reduction from a distinguisher to trapdoor recovery would be needed for that step. This is a proof gap, not evidence that such a distinguisher exists at the submitted parameters. No forgery or key recovery follows from the observation.

### Reproducing

```sh
python3 sign-09/reproduce_search_decision_gap.py
```

The source certificate reads the frozen specification and checks the search definition, the public-key replacement, and the claimed equivalence. It does not run a cryptanalytic attack.

## sign-09-3: Signing and verification read beyond declared input buffers

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: DOVE-128, -256 and -512 classic and pkc_skc reference variants; the supplied performance-optimal packages contain byte-identical source copies
Discovery: Trivial
Exploitation: Short API inputs cause out-of-bounds reads; pkc_skc signing also over-reads an exact-size secret key, with no disclosure or forgery shown
Credit: 潇湘 (lxx, NGCC PKC Forum sender) for the ignored lengths; exact-size pkc_skc over-read identified by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-15
Original source: [DOVE assessment attached to the PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/PLF54PXYLAT2LQFQLJWN5LMKWSWWSM7O/attachment/7/DOVE_security_assessment.md)

The submitted `sig_sign` routines accept `sk_len_bytes` but do not check it before reading the fixed secret-key layout. Both `sig_verify` variants likewise ignore `pk_len_bytes` and `sn_len_bytes` while parsing the public key and signature at fixed offsets (`DOVE_classic_ref/SIG_AlgorithmInstance.c:234–250,374–395`; `DOVE_pkc_skc_ref/SIG_AlgorithmInstance.c:160–178,306–325`). A caller-supplied short buffer is therefore read past its declared allocation.

The pkc_skc signing path also over-reads a key of its *own advertised size*. `sig_get_sk_len_bytes()` returns only `DOVE_SK_SEED_BYTES`, and key generation writes only that seed (`SIG_AlgorithmInstance.c:44–47,137,154–155`). Before deriving the trapdoor from the seed, signing copies a `DOVE_V × DOVE_O` matrix from `sk + DOVE_SK_SEED_BYTES` (`:165–169`, `matrix.c:46–48`): 2,992, 15,360 or 77,760 bytes beyond the 128-, 256- or 512-level seed. The derived matrix immediately overwrites that copy, so the read has no demonstrated cryptographic consequence, but it is an out-of-bounds read on an ordinary exact-size API call. The submitted KAT driver allocates precisely the reported secret-key length (`KAT_SIG.c:96–100`).

### Reproducing

```sh
sh sign-09/reproduce_input_lengths.sh
```

The witness compiles the frozen DOVE-128 reference code with AddressSanitizer. It confirms short-public-key and short-signature reads in verification, a short-secret-key read in classic signing, and the exact-size pkc_skc secret-key read. It also checks that the source files in the performance-optimal packages are byte-identical. No exploitation beyond the memory reads was attempted.

## sign-09-4: The EUF-CMA proof neither embeds the MQ target nor justifies signature simulation

Severity: Medium
Status: Proof gap
Layer: Design
Affected: DOVE-128, -256 and -512 security proof, both classic and pkc_skc variants
Discovery: Moderate
Exploitation: Theorem 1 does not establish its MQ-target reduction or the claimed signature-distribution equivalence; no signature forgery or key recovery is demonstrated
Credit: Haotian (NGCC PKC Forum sender); unsalted pre-query consequence by Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-10-24
Original source: [Haotian's PKC Forum comment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/J34BWSBLHSX2VOX5MNUTW6KQ6W26APU3/)

Theorem 1's Game 2 (§4.4, physical p. 15) claims that a forgery solves a supplied DOVE-MQ instance. That challenge contains both a map and an independently chosen target (Definition 1, p. 14). The proof replaces the public map and extracts a preimage of the forged-message hash, but never links that hash to the supplied target. A guess-the-hash-query embedding would introduce a loss that the claimed reduction does not account for.

Game 2 also samples a uniform signature vector `s`, sets the hash target to `P*(s)`, and asserts that this simulates signing. The submitted signer instead retries vinegar choices when its linear system is singular (`DOVE_classic_ref/SIG_AlgorithmInstance.c:297–337`); no bound establishes that the resulting signature distribution matches the simulation. Because the submitted target is unsalted (Sign and Verify, physical pp. 8–9), Game 2 additionally aborts if the adversary hashes a message before requesting its signature, despite bounding that abort as negligible. This last consequence shares the missing salt binding already present in the submitted construction; the target-embedding and distribution gaps do not depend on it. None of these proof gaps demonstrates a distinguisher, forgery or key recovery.

### Proposed fixes

Haotian suggests binding a fresh salt to the hash target and points to a [modified UOV approach](https://eprint.iacr.org/2024/609) that fixes one vinegar choice while retrying salt on inconsistency. These would change the submitted algorithm and are recorded without evaluating a revision.

### Reproducing

```sh
python3 sign-09/reproduce_euf_simulation_gap.py
```

The certificate checks the frozen MQ definition, the theorem's target-extraction and simulation assertions, the submitted Sign/Verify hash inputs and the singular-system retry. It checks the unsalted pre-query consequence separately; it does not attack the real signer or prove the two signature distributions distinguishable.
