<!-- synchronized report: sign-13/report.md -->
Candidate: GreatWall Signature Algorithm
Family: Symmetric-key (VOLE-in-the-head) signature
Archive: [GreatWall.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/GreatWall.zip) (SHA-256: `814cd3b977ddc0cc59828861c145580473b1a62a66da852b078edbaf689f5a8d`)

## sign-13-1: SHAKE256 capacity reduces GreatWall-512 forgery cost to about 2^256

Severity: Critical
Status: Confirmed
Layer: Design
Affected: GreatWall-512s and GreatWall-512f
Discovery: Moderate
Exploitation: Approximately 2^256 classical Keccak evaluations and one signing query
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-30
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/UCS5CCGZNZYKBBJZAE6PKT275GPRPGGP/)

GreatWall specifies `H1 : {0,1}* -> {0,1}^{2λ}` as collision resistant and instantiates every hash with SHAKE256 when `λ>128` (§2.3.4). For the 512-bit sets, signing and verification compute `mu=SHAKE256(pk || m || 0x01,1024)` (Algorithms 2 and 13; `faest.c:351–355,542–546`). The 1024-bit output does not raise SHAKE256's 512-bit sponge capacity.

For the fixed public-key prefix, a birthday search over one controlled rate block finds two post-permutation states with equal capacity in about `2^256` work. A second block cancels their public rate difference, making the complete states equal before common padding. The resulting distinct messages have the same `mu`; a signature requested on one therefore verifies unchanged on the other. This is a one-query EUF-CMA forgery at about `2^256` classical work (about `2^170.7` generic quantum queries), below GreatWall's 512-bit classical claim and therefore Critical.

### Reproducing

```sh
python3 sign-13/reproduce_shake_capacity.py
```

The witness checks the archived SHAKE256 selection and message-hash path, then executes the exact two-block construction in a scaled permutation model. It certifies the structural attack and full-size generic bound; it does not perform the infeasible `2^256` search.
