<!-- synchronized report: kem-03/report.md -->
Candidate: BAG-Loong
Family: Code-based (rank metric)
Archive: [BAG-Loong.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BAG-Loong.zip) (SHA-256: `2795fd57d3d00791652256362b4a21982116d3aad1fb63633dac923e0e76e05b`)

## kem-03-1: Secret-dependent pivoting in the Gabidulin decoder

Severity: Medium
Status: Confirmed
Layer: Side-channel
Affected: Reference implementations, all four parameter sets
Discovery: Moderate
Exploitation: Local control-flow/cache observer; key recovery not demonstrated
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-23

Decapsulation forms a rank-code word by multiplying the public ciphertext component by secret `x` and adding the second ciphertext component (`src/loong_pke.c:1003-1014`). The Gabidulin decoder then searches for a pivot with a discrepancy-dependent `while` loop, swaps at the chosen index, and branches into different polynomial-update paths (`src/gabidulin.c:213-279`). The executed path and addresses thus depend on the recipient secret, not just public ciphertext. A co-resident timing/cache observer can learn information about the intermediate. No inversion from observed pivot sequences to the private vector, full key-recovery attack, or remote channel is shown; a key-dependent pivot is not by itself a Critical break.

### Reproducing

The source-level witness is the decapsulation call in `src/loong_kem.c:217-218`, the secret-key product in `src/loong_pke.c:1003-1014`, and the value-dependent pivot loop in `src/gabidulin.c:213-279` under `Implementations/Reference_Implementation/Loong-Block-ms-128/`. The same files occur in the other reference parameter directories. See `constant_time.md` for the secret/public classification.

## kem-03-2: The rejection key does not bind the received ciphertext

Severity: High
Status: Confirmed
Layer: Design
Affected: All BAG-Loong parameter sets
Discovery: Moderate
Exploitation: Observable rejection keys give a plaintext-checking and decoding-failure oracle; challenge-key recovery is unshown
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-25

Algorithm 2 (§1.4) specifies `K(ξ, ct')` on rejection, where `ct'` is the re-encryption of the decrypted message rather than the received ciphertext. The code follows it (`loong_kem.c:229–246`). Distinct invalid ciphertexts with the same decryption therefore share a rejection key, exposing a plaintext-checking and decoding-failure oracle when keys are observable. This departs from standard Fujisaki–Okamoto rejection, so the stated IND-CCA2 proof does not establish the submitted construction's claim. A mauled challenge returns `K(ξ, c*)`, not the challenge key `K*`; the witness demonstrates rejection-key collisions, not challenge-key recovery or a full IND-CCA2 attack.

### Reproducing

```sh
python3 kem-03/reproduce_rejection_key.py kem-03/lib/libBAG-Loong-128.so
```
