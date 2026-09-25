<!-- synchronized report: sign-29/report.md -->
Candidate: Tins
Family: Multivariate (MPC-in-the-head)
Archive: [Tins.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Tins.zip) (SHA-256: `84affc1f7cbdeec48a7cb6df3349b5708644672f2ac12140c529e74f6d57ca21`)

## sign-29-1: One signature reveals the complete signing witness

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Tins128, Tins256, and Tins512
Discovery: Non-trivial
Exploitation: One signature and binary Gaussian elimination on at most 1,044 unknowns
Credit: Tianyuan Xie
Date: 2026-09-22
Original source: [NGCC PKC Forum report](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ECMH3PMGM2NWJG4JIBQBCKQ6U5CBUDDA/)
Follow-up source: [Tins team's 2026-09-25 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AJF5VVYQAJTICBWFFS5DHIO4U2FZZOXT/)

Tianyuan Xie reported the attack in the [NGCC PKC Forum](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/ECMH3PMGM2NWJG4JIBQBCKQ6U5CBUDDA/). Tins masks its binary witness `(alpha,beta)` with vectors over the 12-bit subfield, while publishing `p_mid` in `GF(2^k)`. After substituting the verifier-reconstructed evaluations into `p_mid`, the bilinear witness terms cancel in characteristic two. Only a 12-bit additive mask remains, confined to the final subfield coefficient.

Every execution therefore exposes `k-12` public binary equations in the `2(n-2)` witness bits. Two executions from one signature have full rank for each submitted set: the reported ranks after the first and second executions are 264 then 276, 516 then 532, and 1,032 then 1,044. Recovering the witness is deterministic and inexpensive; the witness satisfies the public NSBC relation and can run the specified signer on arbitrary messages, violating EUF-CMA.

The local reproducer independently performs the attack on a fresh Tins128 key and signature. It uses only the public key and signature after signing, obtains rank 276/276 from two executions, and validates the recovered witness against the public relation. Xie additionally reports end-to-end accepted forgeries on all three sets and exact recovery from all ten usable Tins128 and Tins256 KAT signatures.

On 2026-09-25, the Tins team [confirmed Xie's attack and withdrew the proposal](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AJF5VVYQAJTICBWFFS5DHIO4U2FZZOXT/). They said sampling the masking polynomial over the smaller subfield had been a known design risk chosen for efficiency.

### Reproducing

```sh
make -C sign-29 exploit
```
