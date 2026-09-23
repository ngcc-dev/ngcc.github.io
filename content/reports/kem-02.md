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
Layer: Implementation
Affected: Reference implementations, all five parameter sets
Discovery: Moderate
Exploitation: Local cache/control-flow observation; no separate extraction demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

The Amoeba decapsulator decrypts under the private key and ECC-decodes the resulting codeword. Its Hamming decoder branches on each codeword bit and on the syndrome, then loads `syndrome_map[s_h_key]` (`src/backend/hamming.c:131,157-183`). Both the branch decisions and the table address derive from secret-key decryption of the ciphertext. This is a local control-flow/cache side channel independent of `kem-02-1`'s faulty ciphertext comparison. The code also returns an explicit decoder-failure bit (`ccakem.c:61-62`), but neither that bit nor this trace has been turned into a second demonstrated key-recovery oracle. A candidate-specific chosen-ciphertext recovery argument is still needed; that is why this finding remains Medium.

### Reproducing

Follow `src/backend/ccakem.c:60-80` → `src/backend/cpapke.c:438-447` → `src/backend/hamming.c:131,157-183` under `Implementations/Reference_Implementation/Amoeba-576/`; the same decoder pattern appears in the other reference sets. This is a source-level witness, not a measured timing benchmark. See `constant_time.md` for the secret/public classification.
