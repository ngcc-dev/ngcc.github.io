<!-- synchronized report: sign-14/report.md -->
Candidate: Lynxer
Family: VOLE-in-the-head signature
Archive: [Lynxer.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Lynxer.zip) (SHA-256: `34d863f7df8979c4a5e27fcfe657ed54e81905115c0afc8ef749f50af432f928`)

## sign-14-1: A degenerate QuickSilver witness gives universal public-key-only forgeries

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Lynxer-256s/f, -384s/f, and -512s/f; the 160-bit sets use different constraints
Discovery: Non-trivial
Exploitation: Comparable to one honest signature; full-size forgeries reproduced at all six affected parameter sets
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-27
Original source: [Feussner's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/JMTZL5V7ROPXSFJQWRHIOKLORGI5AJSN/) and [pinned public analysis and reproducer](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/d03848f40a49a1d1d146e33c88ce251ac092439d/Lynxer)
Follow-up source: [Lynxer team's confirmation and fix](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/TJ3HPFROBMZMNMEHDEC3IQRO7R7QHQAQ/)

Additional reference: [Liu et al., ePrint 2026/2235](https://eprint.iacr.org/2026/2235)

The specified QuickSilver relation fails to enforce two nonzero conditions. Set the purported Lynx key to the public constant `c3` and the first S-box output `v1` to zero. Every term in the first constraint then vanishes; the final constraint loses the public target because both its products contain either `v1` or `k+c3`. The attacker publicly evaluates the second S-box to satisfy the sole remaining constraint. This gives a false witness for every public key and message without a signing query or Lynx preimage.

We reran the pinned attack against all six affected full reference parameter sets. Each secret-key buffer was erased before attack construction, direct Lynx evaluation confirmed that the forged key was not a victim preimage, the ordinary submitted verifier accepted the fresh-message signature, and a changed-message control rejected. The 160-bit relations differ and are not claimed to be vulnerable.

The Lynxer team confirms the flaw, reports that the Center for Cryptology Study at Tsinghua University found it independently, and replaces the original S-boxes with inversion in [ePrint 2026/1099](https://eprint.iacr.org/2026/1099). That revision is intended to enforce the relation over the full key space and blocks this attack; the archived Round 1 submission remains affected.

Liu et al. independently formalize the same null-branch witness mechanism, prove public-key-only forgery for the affected 256-, 384-, and 512-bit Lynxer relations, and report accepted fresh-message forgeries. Their separate Lynx-192 analysis concerns another upstream variant and does not extend this finding to the archived NGCC 160-bit sets.

On 2026-09-29 the Lynxer team also [released a targeted modification note](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/3HMAZXK7HD6JDLF5BJVYWDECM2SF5N3M/) for the anomalous-point attack. It concerns the repaired revision, not the archived Round 1 package tested here.

### Reproducing

```sh
make -C sign-14 exploit-public-forgery
```

The wrapper checks out the pinned public reproducer, verifies the official source-archive hash, compiles against the archived reference code, and runs all six positive and changed-message controls. It requires Git, curl, unzip, and a C compiler.
