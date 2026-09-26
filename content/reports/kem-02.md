<!-- synchronized report: kem-02/report.md -->
Candidate: Amoeba
Family: Lattice-based (Ring-LWE)
Archive: [Amoeba.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Amoeba.zip) (SHA-256: `719c438a30cccd72c9d83da4b5150fee0c55351f2c13e7a66fd61bf653ca5c24`)

## kem-02-1: The FO check compares only every fourth ciphertext byte

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: All five Amoeba reference parameter sets
Discovery: Trivial
Exploitation: Full Amoeba-576 key recovery independently reproduced in 128,161 decapsulation queries; reporter used approximately 30,000
Credit: Jinnuo Li
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JB6IBZZUEVGTMM2SF6WK5PIYW7ESSPYT/)

Jinnuo Li reported the attack in the [NGCC PKC Forum](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JB6IBZZUEVGTMM2SF6WK5PIYW7ESSPYT/). Amoeba's Fujisaki--Okamoto decapsulation re-encrypts the decoded message, but `cmp()` advances its byte index by four. Amoeba-576 consequently checks only 262 of 1,047 ciphertext bytes; changes in the other 785 bytes cannot trigger implicit rejection. The same source defect appears in every submitted parameter set.

This exposes a plaintext-checking primitive of the type developed by Das in [ePrint 2026/1682](https://eprint.iacr.org/2026/1682): unchecked ciphertext coefficients can be swept across decoding thresholds to obtain linear information about the reused Ring-LWE secret. Li reports recovering all ten official Amoeba-576 KAT secret keys in about `3*10^4` decapsulation queries per key. Our independent witness uses a blind external-parity coordinate as a controlled first error, then binary-searches 320 other blind coordinates per chosen ciphertext. It recovers all 576 secret coefficients from 80 ciphertexts and 128,161 oracle calls, constructs a new decapsulation key without copying the original secret-key bytes, and recovers ten fresh honest encapsulations' shared secrets. Seeds 1, 2, and 3 reproduced. The measurement and regression are local and finish in about 17 seconds on this 28-vCPU host; they are less query-efficient than Li's method.

The attack assumes a reused KEM key and an observable valid-plaintext/derived-key signal. The local witness models that signal using the decapsulation output and an attacker-computable candidate key. An application that never exposes a usable downstream accept/reject signal is not shown vulnerable to remote key recovery by this witness.

The fix is to compare the complete ciphertext in constant time. A full-byte comparison is also required by the scheme's stated FO construction and IND-CCA2 argument.

### Reproducing

```sh
make -C kem-02 exploit
```

The source-level witness verifies the vulnerable loop in all five trees, enumerates the 262 checked positions for Amoeba-576, and exercises checked and unchecked mutation controls.

For independent end-to-end recovery, use Sage's Python (with NumPy and SciPy):

```sh
make -C kem-02 exploit-key-recovery PYTHON=/path/to/sage/bin/python
```

The attack-only library is linked from the same submitted Amoeba-576 object files as the normal harness library, but additionally exports the public CPA encryption and hash helpers needed to make chosen valid ciphertexts. It does not patch the candidate's comparison or decoder. The original secret key is supplied only to the decapsulation oracle and to score the recovered coefficients; the reconstructed key and fresh shared-secret checks do not copy it. A checked-byte mutation is a negative control.

## kem-02-2: Secret-derived ECC decoding indexes a syndrome table

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all five parameter sets
Discovery: Moderate
Exploitation: Local cache/control-flow observation; no separate extraction demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The Amoeba decapsulator decrypts under the private key and ECC-decodes the resulting codeword. Its Hamming decoder branches on each codeword bit and on the syndrome, then loads `syndrome_map[s_h_key]` (`src/backend/hamming.c:131,157-183`). Both the branch decisions and the table address derive from secret-key decryption of the ciphertext. This is a local control-flow/cache side channel independent of `kem-02-1`'s faulty ciphertext comparison. The code also returns an explicit decoder-failure bit (`ccakem.c:61-62`), but neither that bit nor this trace has been turned into a second demonstrated key-recovery oracle. A candidate-specific chosen-ciphertext recovery argument is still needed; that is why this finding remains Medium.

### Reproducing

Follow `src/backend/ccakem.c:60-80` → `src/backend/cpapke.c:438-447` → `src/backend/hamming.c:131,157-183` under `Implementations/Reference_Implementation/Amoeba-576/`; the same decoder pattern appears in the other reference sets. This is a source-level witness, not a measured timing benchmark. See `constant_time.md` for the secret/public classification.

## kem-02-3: The decryption-failure bound omits detected two-error rejections

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All five Amoeba parameter sets; Amoeba-576's modeled bound falls below its 128-bit target
Discovery: Moderate
Exploitation: Failure-bound/proof mismatch; no separate full-size key recovery demonstrated
Credit: Yijian Liu (with AI assistance)
Date: 2026-09-23
Original source: [NGCC PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/35SR56KWDUXV5KRSKBU6TXO3LW25CMOC/)

Section 2.3.2 says the shortened extended Hamming decoder corrects one error but **rejects** exactly two. Nevertheless its quoted decryption-failure bound uses only the probability of three or more errors. The submitted `CPAPKE_Decrypt` returns `-1` when `decode_ECC` detects two errors, and `CCAKEM_Decaps` propagates that rejection. Those events must count when bounding honest key-agreement failures and the PKE failure term used in §3.1.2's CCA reduction.

Under the submission's own Gaussian and independent-bit approximation, counting two-error events changes the Amoeba-576 tail from `2^-130.2722` to `2^-86.1221`; the calculation in the official archive's `Security/noise_estimation.ipynb` gives both numbers, while Table 4 quotes a roughly `2^-133.3` failure claim. The revised figure is **not** a measurement or certified bound for correlated implementation noise, and this accounting flaw is not a second demonstrated key-recovery attack.

### Reproducing

```sh
python3 kem-02/reproduce_dfr_tail.py
```

This is a static/model calculation, not a runtime failure measurement. The standalone script reproduces all five two- and three-error tails from `Security/noise_estimation.ipynb` in the official Amoeba archive; the notebook need not be present to run the script. Inspect `hamming.c:157-183`, `cpapke.c:438-447`, and `ccakem.c:60-63` in the Amoeba-576 reference tree for the actual rejection path.

## kem-02-4: A one-bit ciphertext change writes outside the Hamming correction buffer

Severity: High
Status: Confirmed
Layer: Implementation
Affected: All five Amoeba reference parameter sets
Discovery: Moderate
Exploitation: One malformed ciphertext aborts decapsulation; no code execution demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

The Hamming `syndrome_map` (`hamming.c:8`) holds check-bit positions up to 1023, but the correction buffer `c_corr` has 523 bytes, and `hamming.c:177` flips `c_corr[q]` without a bound check. Flipping the top bit of one compressed `c2` coefficient makes decapsulation write past the buffer; stack protection then aborts the process in every parameter set.

The same incorrect syndrome mapping can be reached by an honest ciphertext with one noise error on a check coefficient at positions 516–521, so this is also a decapsulation reliability defect. The witness now tests a neighboring check bit whose mapped correction stays inside the buffer; it returns without aborting in all five sets.

### Reproducing

```sh
python3 kem-02/reproduce_ecc_stack_write.py
```

## kem-02-5: Withdrawn — unseeded caller repeats Amoeba keys

Severity: Info
Status: Withdrawn
Layer: Evaluation
Affected: Unseeded calls to all five Amoeba reference parameter sets
Discovery: Trivial
Exploitation: None under the caller-seeded NICCS API
Credit: Jiadong Han
Date: 2026-09-26
Original source: [Han's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/MRNBLY5HODKCWN6VLWETBR3W4VE3CDZC/)

The official NICCS API makes the caller responsible for randomness: its KAT driver defines `drng_algorithm` (`api/API_PKC/Implementations/Reference_Implementation/AlgorithmInstance/KAT_KEM.c:42`) and seeds it before key generation (`:105`). The algorithm code normally declares this state `extern`. Amoeba instead defines the global in `cpapke.c:13`, so an unseeded caller still links and silently uses the zero-initialized state. Its unused `CPAPKE_Init()` helper (`:15-19`) suggests initialization but is not called by `kem_keygen`.

Fresh unseeded processes return identical Amoeba keys, while two explicitly seeded processes differ. The same unseeded-process test also repeats keys for Aigis-Enc+, Mithril, UVW, BAG-Loong and BRA. This is a consequence of omitting the caller's required seeding step, not an Amoeba-specific universal key pair. The finding is withdrawn; Amoeba's self-defined global is a robustness concern, not a demonstrated break of correctly seeded key generation.

### Reproducing

```sh
make -C kem-02 check-unseeded-keygen
```

The check launches two fresh child processes per parameter set and compares `SHA-256(pk || sk)`, then repeats with two explicit distinct seeds as a control. It demonstrates the effect of violating the API's seeding contract.
