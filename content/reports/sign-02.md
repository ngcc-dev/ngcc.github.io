<!-- synchronized report: sign-02/report.md -->
Candidate: BiT
Family: Lattice-based
Archive: [BiT.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip) (SHA-256: `698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d`)

## sign-02-1: A 512-bit unsalted message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-512 specification, reference and optimized implementations
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

BiT-512 claims 512-bit classical security and normatively computes the message representative `mu = H(tr || M)` as a 512-bit value. This fixed unsalted representative has only 256 bits of generic collision resistance.

After finding distinct messages with the same `mu`, an attacker requests a signature on one and transfers it unchanged to the other. Later signing randomness cannot distinguish the already-colliding messages. The reference implementation uses the same 64-byte representative.

This is a specification-level design break of the advertised 512-bit classical EUF-CMA level. It is a generic `2^256` security ceiling, not a computation performed by the harness.

### Reproducing

```sh
python3 security/design_parameter_audit.py --report-id sign-02-1
```

The check verifies the normative BiT-512 construction on physical PDF pages 18 and 33–34 and the 64-byte source constant.

## sign-02-2: A shared bimodal sign leaks an equivalent BiT-128 signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-128; the same shared-sign construction appears in the other sets, but their recovery costs were not established
Discovery: Non-trivial
Exploitation: Equivalent-key recovery from 200,000 public signatures and a fresh-message forgery accepted by the unmodified verifier; a changed-message control rejects
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/84_EKMOtk_M/m/ZNMqLQ07BAAJ)

Additional reference: [Xiong and Wang, ePrint 2026/2232, 2026-09-29 revision, §8](https://eprint.iacr.org/archive/2026/2232/1790653241.pdf)

BiT uses one hidden sign for the entire response, but its rejection rule corrects each coefficient against a *scalar* mixture. The joint response remains a mixture of two product distributions and retains secret-dependent cross-coordinate correlations even when the individual marginals have the intended distribution. The response to the known constant component gives an observation of the common sign, allowing the remaining response components to reveal the signing secret statistically. Figures 2 and 4 specify a single sign bit per signature with coefficientwise rejection; §3.1.3’s assertion that “z is independent of b” fails for the joint response. The reference source has the same pattern (`sign.c:134–153`, `sample.c:124–259`). The mechanism does not depend on a hash weakness.

The released public-transcript attack streams 200,000 signatures from an ordinary signing oracle, statistically recovers a candidate key, repairs low-confidence coefficients by a public search when the candidate fails the compressed public-key relation (in our run, 1,596 candidates over 24 search bits), completes an equivalent key that satisfies the relation, and produces a fresh-message signature accepted by the unmodified BiT-128 verifier. A changed-message control rejects. We reproduced its fixed key-0 experiment in 164 CPU-seconds on a single-threaded `Intel Core Processor (Broadwell, IBRS)` validation VM; the attack never reads or compares the generated secret key. This upgrades the finding from Probable to Confirmed. The authors report three of four fixed keys succeeding at 200,000 signatures and the fourth at 250,000; no success-rate claim beyond those experiments is made.

Follow-up analysis: the [BiT team's 2026-09-29 response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/74QWBAYF4KZYN5HDHM2ROENQUDVWAUGT/) confirms this shared-sign issue and says that the distinct compressed-public-key leakage reported for CS also applies to the earlier BiT version. No BiT-specific derivation, transcript, or witness for that second route accompanied the response. Since the confirmed shared-sign route already yields equivalent-key recovery and forgery, the additional statement is retained as follow-up evidence rather than assigned a separate vulnerability ID.

### Reproducing

```sh
sign-02/reproduce_bimodal_key_recovery.sh
```

The wrapper downloads and hash-checks both Feussner's [attack package at commit `91f2ddf`](https://github.com/martinfeussner/NGCC-Signature-Audit/tree/91f2ddf0590a24ad39afc2ce2ee4f2627ec54726/BiT) and the official BiT submission archive. It runs the fixed 200,000-signature key-0 experiment and requires equivalent-key recovery, fresh-message acceptance and changed-message rejection.
