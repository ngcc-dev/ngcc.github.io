<!-- synchronized report: sign-15/report.md -->
Candidate: MORNING-ATLAS
Family: Lattice (Module-LWR, Fiat-Shamir)
Archive: [MORNING-ATLAS.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/MORNING-ATLAS.zip) (SHA-256: `c796b106a7d43b2b3d6110ec2be426aa321cc7336f39a2cc027b2d6e8b4cc8c1`)

## sign-15-1: Returned-length error causes an out-of-bounds heap disclosure

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference API and supplied KAT, all four parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Song-Anxiao's independent assessment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QUKIQWX7B5D2UYVTGSZ3JC6IVELQWA2Q/)

`sig_get_sn_len_bytes()` advertises a `CRYPTO_BYTES`-byte output buffer. `sig_sign()` writes exactly that detached signature, but returns `CRYPTO_BYTES + message_length` as though it had also appended the message. A caller that allocates the advertised size and serializes the returned length reads beyond the allocation.

The submitters' own KAT does exactly this. In its first records, the out-of-bounds `Sn` field contains allocator bytes followed by 41, 45, 40, and 41 bytes of the adjacent 64-byte KAT seed for the 128-, 192-, 256-, and 512-bit instances. From record 3 onward it includes all 64 seed bytes. That seed deterministically generates the KAT key material.

The KAT format also prints `Seed` and `SK` as separate fields, so these published vectors do not newly expose an otherwise secret value. They nevertheless provide a concrete demonstration that trusting the candidate's returned length discloses adjacent heap data; in another caller the adjacent object may be private. This is a serious API/memory-disclosure defect, distinct from the cryptographic malleability below.

### Reproducing

Inspect the included reference `lwrdsa128/SIG_lwrdsa128.c` at lines 33–34
(advertised buffer length) and 428 (returned length), then `lwrdsa128/KAT_SIG.c`
at lines 97–100 and 136–144 (allocation and output). The other three levels
have the same pattern. To check the quoted out-of-bounds **bytes** in the
submitter's KAT text, download and extract the official archive; the bulky
original KAT files are not retained in this harness.

```sh
rg -n 'return CRYPTO_BYTES|m_len_bytes \+ CRYPTO_BYTES|calloc\(sn_len_bytes|fprintstr\(file_output, "Sn = "' sign-15/Implementation/Reference_Implementation/lwrdsa128/{SIG_lwrdsa128,KAT_SIG}.c
IDS=sign-15 ./download.sh
./extract.sh sign-15
```

## sign-15-2: Trivial hint-padding malleability violates SUF-CMA

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference implementation, all four parameter sets
Discovery: Trivial
Exploitation: Trivial
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Song-Anxiao's independent assessment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QUKIQWX7B5D2UYVTGSZ3JC6IVELQWA2Q/)

The signature decoder stops after the cumulative number of encoded hint indices but does not require the remaining fixed-size hint slots to be canonical. Verification compares only the decoded algebraic values and ignores changes in those unused slots.

For each of `lwrdsa128`, `lwrdsa192`, `lwrdsa256`, and `lwrdsa512`, flipping the high bit of the final unused hint-index byte in a valid signature produced a different byte string that still verified for the same message and public key.

The attack needs only one ordinary valid signature. It does not forge a new message and therefore does not by itself violate EUF-CMA, but it directly violates the specification's SUF-CMA claim.

Verification must reject any noncanonical unused hint slot and enforce all stated hint-weight and ordering constraints. The separate heap over-read (`sign-15-1`) and ATLAS-192 parameter shortfall (`sign-15-3`) are reported on this page and are not needed for this attack.

### Reproducing

```sh
make -C tools
make -C sign-15
for lib in sign-15/lib/*.so; do
    tools/ngcc_attack sig-hint-padding "$lib"
done
```

Each parameter set prints `CONFIRMED`: the driver changes bit 7 in an ignored
hint slot, restores the message buffer that this verifier unexpectedly
overwrites, and requires the byte-distinct signature to verify.

## sign-15-3: The ATLAS-192 challenge space is below 192 bits

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: ATLAS-192 reference and optimized implementations; specified parameter set unaffected
Discovery: Trivial
Exploitation: Exact parameter shortfall; no separate attack required
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21
Follow-up source: [Song-Anxiao's independent assessment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QUKIQWX7B5D2UYVTGSZ3JC6IVELQWA2Q/)

The submitted ATLAS-192 implementation uses `n=128` and `kappa=64`. Its challenge space therefore has

`log2(binomial(128,64) * 2^64) = 188.17143`

bits, below the advertised 192-bit level. The specification instead selects `kappa=69`, which gives about 192.61 bits. This is an implementation-only parameter mismatch, not a defect in the specified parameter set.

The submitted source acknowledges the mismatch directly: `params.h` comments that “KAPPA should be 69 not 64” and attributes the temporary value to an implementation limitation.

### Reproducing

Reproduce the exact cardinality and source check with:

```sh
python3 security/design_parameter_audit.py --report-id sign-15-3
```

## sign-15-4: Repeated masking coefficients expose the signing key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: ATLAS-128, ATLAS-192, and ATLAS-256 reference and optimized implementations; ATLAS-512 is unaffected
Discovery: Moderate
Exploitation: Two valid signatures recover `s1` in polynomial time and enable new-message forgery
Credit: Xianhui Lu and Yijian Liu, with AI assistance
Date: 2026-09-23
Original source: [Yijian Liu's NGCC PKC Forum post on behalf of Xianhui Lu](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/L5UNKA72RZ2TBTCKZYIVJ5KFDU6XTWFB/)
Follow-up source: [Song-Anxiao's independent assessment and proof-premise check](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QUKIQWX7B5D2UYVTGSZ3JC6IVELQWA2Q/)

In `rej_gamma1m1()`, the second 20-bit decode overwrites `t` before either accepted coefficient is stored. Every masking polynomial therefore has `y[2i] = y[2i+1]`. Since the signature contains `z = y + c*s1` modulo `q`, subtracting each adjacent response pair cancels the mask and gives a noiseless linear equation in the secret `s1`. Two signatures supply a full-rank system for each secret polynomial in all three affected profiles. ATLAS-512 uses a separate three-byte sampler branch.

The local witness solves those equations using only two public, officially verified signatures, recovers every `s1` coefficient, and checks zero residuals on two further signatures. It then reconstructs the remaining signing-key fields from `s1` and the public key, chooses a fresh signing-randomness key, and produces a new-message signature accepted by the submitted verifier. It never uses the original secret key in the recovery or forgery stage.

### Reproducing

```sh
mamba run -n sage python sign-15/reproduce_mask_key_recovery.py
```

The command uses this host's Sage environment; elsewhere, use any Python with `sage.all` importable. The witness compiles only the archived reference and optimized C sources in a temporary directory. It prints six `CONFIRMED sign-15-4` lines, one for each affected implementation/profile combination. The optimized builds require AVX2.

## sign-15-5: Unchecked hint decoding causes out-of-bounds reads and writes

Severity: High
Status: Confirmed
Layer: Implementation
Affected: Reference verifiers, all four parameter sets
Discovery: Trivial
Exploitation: Unauthenticated out-of-bounds reads and writes; downstream control is unshown
Credit: Song-Anxiao, with Xuanzhi CryptoLLM assistance
Date: 2026-09-27
Original source: [Song-Anxiao's PKC Forum assessment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QUKIQWX7B5D2UYVTGSZ3JC6IVELQWA2Q/)

`unpack_sig` takes both its loop limit and coefficient indices from the unauthenticated hint encoding, before checking the signature. In ATLAS-128 (`packing.c:223-224`) and -192 (`:218-219`), it writes `h->vec[i].coeffs[sig[j]] = 1` without checking that a byte-sized position is below `N=128`; a position such as 200 writes beyond the coefficient array. The count is also unchecked. In ATLAS-256, a count of 255 reads beyond the signature buffer. In ATLAS-512, it reads beyond `h_coeffs[OMEGA]` and can use the stray value as an index for a coefficient write.

The local witness links the submitted `packing.c` and calls the decoder used by verification. AddressSanitizer confirms four-byte heap-buffer-overflow writes in the 128- and 192-bit sets, a signature-buffer over-read in the 256-bit set, and an out-of-bounds hint-array read in the 512-bit set. In the submitted verifier the decoded output is on the stack, so the first two writes corrupt its frame.

### Reproducing

```sh
make -C sign-15 exploit-memory-safety
```

The target runs all four reference parameter sets.

## sign-15-6: Withdrawn — official NICCS DRNG rotates by the word size

Severity: Info
Status: Withdrawn
Layer: Evaluation
Affected: Shared official NICCS API DRNG, not ATLAS specifically
Discovery: Trivial
Exploitation: No ATLAS-specific vulnerability established
Credit: Song-Anxiao, with Xuanzhi CryptoLLM assistance
Date: 2026-09-27
Original source: [Song-Anxiao's PKC Forum assessment](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QUKIQWX7B5D2UYVTGSZ3JC6IVELQWA2Q/)

The undefined shift is real: the SM3 helper in `drng.c:36` evaluates `(a << n) | (a >> (32-n))` with `n=0` reached at line 90. But the candidate's `drng.c` is the official NICCS API file, with only a final-newline difference in the archived copies. The same rotation appears across submissions that use that shared file. ATLAS calls the DRNG during key generation, not signature generation. This is an upstream API portability issue rather than an ATLAS-specific finding, so this report is withdrawn.

### Reproducing

Compare `sign-15/Implementation/Reference_Implementation/lwrdsa128/drng.c` with `api/API_PKC/Implementations/Reference_Implementation/AlgorithmInstance/drng.c` after normalizing the final newline.

## sign-15-7: Finite mask support leaks the specified ATLAS-128 signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: ATLAS-128 as specified; the other parameter sets were not claimed or tested
Discovery: Non-trivial
Exploitation: 3,000,000 ordinary chosen-message signatures; 996 seconds in our 12-worker rerun, followed by key recovery and forgery
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-27
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3BUUSX5DBW37Y35QAEXA53ZAEU3JBDET/) and [pinned public analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/d03848f40a49a1d1d146e33c88ce251ac092439d/MORNING-ATLAS)

The specification samples each mask coefficient from the finite interval `[-(gamma1-1), gamma1-1]`, publishes `z=y+c*s1`, and accepts only `|z| < gamma1-beta1`. Its translated-interval argument on pages 17–18 needs `|c*s1| <= beta1`; ATLAS-128 instead has `gamma1=2^19`, `beta1=51`, and `kappa*eta=31*16=496`. About 34% of coefficients exceed `beta1`, so this is not a rare tail. Intersection with the finite mask support loses `(|c*s1|-51)+` possible values and makes boundary responses secret-dependent. Page 21 itself notes that `beta1` is no longer close to `kappa*eta`.

The published recovery converts those boundary events into exact public half-spaces, combines them with the public Module-LWR relation and hint information, recovers all 768 coefficients of `s1` and all 1,152 coefficients of the omitted `t0`, and constructs an equivalent signing key. It uses corrected samplers matching the written distributions, so it is independent of `sign-15-4`'s repeated-mask implementation bug. A calibration key and a prospectively selected second key each yielded an accepted fresh-message forgery from 3,000,000 signatures.

We reran the hash-pinned public evidence and reconstruction checks, then independently ran the complete 3-million-signature pipeline from raw generation for the prospectively selected deterministic key 4. It retained 1,931,974 support rows, recovered a key satisfying all 1,152 public LWR residual bounds, and produced an accepted fresh-message forgery. The run took 996 seconds with 12 collection workers; the changed-message control rejected.

### Reproducing

```sh
make -C sign-15 exploit-spec-key-recovery
ATLAS_FULL=1 NGCC_SAGE_PYTHON=/path/to/python make -C sign-15 exploit-spec-key-recovery
```

The first command uses stored recovered `s1` and `t0` values to rebuild an equivalent key and forgery, then verifies the fresh-message signature and changed-message control. It does not rederive that key from signatures. The second regenerates three million signatures and performs the full public recovery; it needs NumPy, SciPy, and fpylll. Our 12-worker run took 996 seconds; a smaller CPU may take substantially longer.
