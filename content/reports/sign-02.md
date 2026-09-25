<!-- synchronized report: sign-02/report.md -->
Candidate: BiT
Family: Lattice-based
Archive: [BiT.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip) (SHA-256: `698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d`)

## sign-02-1: A 512-bit unsalted message representative caps forgery security at 256 bits

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BiT-512 specification and reference implementation
Discovery: Trivial
Exploitation: Approximately 2^256 hash evaluations
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-21

BiT-512 claims 512-bit classical security and normatively computes the message representative `mu = H(tr || M)` as a 512-bit value. This fixed unsalted representative has only 256 bits of generic collision resistance.

After finding distinct messages with the same `mu`, an attacker requests a signature on one and transfers it unchanged to the other. Later signing randomness cannot distinguish the already-colliding messages. The reference implementation uses the same 64-byte representative.

This is a specification-level design break of the advertised 512-bit classical EUF-CMA level. It is a generic `2^256` security ceiling, not a computation performed by the harness.

### Reproducing

```sh
python3 security/design_parameter_audit.py
```

The check verifies the normative BiT-512 construction on physical PDF pages 18 and 33–34 and the 64-byte source constant.

## sign-02-2: A shared bimodal sign leaks an equivalent BiT-128 signing key

Severity: Critical
Status: Probable
Layer: Design
Affected: BiT-128; the same shared-sign construction appears in the other sets, but their recovery costs were not established
Discovery: Non-trivial
Exploitation: The original analysis reports equivalent-key recovery and an accepted fresh-message forgery from 200,000–250,000 signatures
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/84_EKMOtk_M/m/ZNMqLQ07BAAJ)

BiT uses one hidden sign for the entire response, but its rejection rule corrects each coefficient against a *scalar* mixture. The joint response remains a mixture of two product distributions and retains secret-dependent cross-coordinate correlations even when the individual marginals have the intended distribution. The response to the known constant component gives an observation of the common sign, allowing the remaining response components to reveal the signing secret statistically. Figures 2 and 4 specify a single sign bit per signature with coefficientwise rejection; §3.1.3’s assertion that “z is independent of b” fails for the joint response. The BiT-128 source checkout shows the same pattern (`sign.c:134–153`, `sample.c:124–259`), but those BiT-128 files are absent from the harness. The retained BiT-512 `sign.c:130–150` independently shows the shared-sign construction. The posted analysis reports full equivalent-key recovery and an accepted fresh-message forgery for four independently generated keys; its attack code and those runtime results have not been independently checked here. The mechanism does not depend on a hash weakness.

### Reproducing

Compare the specification's common bimodal bit and coefficientwise RejectSample with the cited source. The [posted analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/84_EKMOtk_M/m/ZNMqLQ07BAAJ) gives the statistical derivation and experimental results; an independent full-scheme witness remains to be added.
