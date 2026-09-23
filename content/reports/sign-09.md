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
